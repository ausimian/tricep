defmodule Tricep.SocketTest do
  use ExUnit.Case, async: false

  alias Tricep.DummyLink
  alias Tricep.Tcp

  # Test addresses
  # local_addr: the address Socket connects TO (like ifaddr in TunLink)
  # remote_addr: the address Socket uses as source (like dstaddr in TunLink)
  @local_addr_str "fd00::1"
  @remote_addr_str "fd00::2"
  @port 8080

  setup do
    # Get binary addresses
    {:ok, local_addr} = Tricep.Address.from(@local_addr_str)
    {:ok, remote_addr} = Tricep.Address.from(@remote_addr_str)

    # Start DummyLink - registers so Socket can find it when connecting to local_addr
    {:ok, link} =
      DummyLink.start_link(local_addr: local_addr, remote_addr: remote_addr, owner: self())

    on_exit(fn -> stop_link(link) end)

    %{link: link, local_addr: local_addr, remote_addr: remote_addr}
  end

  describe "connect/2" do
    test "sends SYN packet when connecting", %{remote_addr: remote_addr, local_addr: local_addr} do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      # Start connect in a task (it will block waiting for SYN-ACK)
      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      # Wait for the SYN packet
      assert_receive {:dummy_link_packet, _link, packet}, 1000

      # Parse the IP packet - Socket sends FROM remote_addr TO local_addr
      <<6::4, _::4, _::24, _payload_len::16, 6::8, _hop::8, pkt_src::binary-size(16),
        pkt_dst::binary-size(16), tcp_segment::binary>> = packet

      assert pkt_src == remote_addr
      assert pkt_dst == local_addr

      # Parse TCP segment
      parsed = Tcp.parse_segment(tcp_segment)
      <<src_port::16, _::binary>> = tcp_segment

      assert src_port in 49_152..65_535
      assert :syn in parsed.flags
      refute :ack in parsed.flags
      assert parsed.ack == 0

      Task.shutdown(task, :brutal_kill)
    end

    test "connect from a bound socket uses the bound source address and port", %{
      link: link,
      remote_addr: remote_addr,
      local_addr: local_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)
      bound_port = 40_020

      on_exit(fn -> stop_socket(socket) end)

      assert Tricep.bind(socket, %{family: :inet6, addr: remote_addr, port: bound_port}) == :ok

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

      <<6::4, _::4, _::24, _payload_len::16, 6::8, _hop::8, pkt_src::binary-size(16),
        pkt_dst::binary-size(16), syn_segment::binary>> = syn_packet

      <<src_port::16, _dst_port::16, _::binary>> = syn_segment
      syn = Tcp.parse_segment(syn_segment)

      assert pkt_src == remote_addr
      assert pkt_dst == local_addr
      assert src_port == bound_port
      assert :syn in syn.flags

      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, bound_port}},
          5000,
          syn.seq + 1,
          [:syn, :ack],
          32768
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      assert Task.await(task, 1000) == :ok
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000
    end

    test "returns eaddrnotavail when all ephemeral ports are exhausted", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      pairs =
        for port <- 49_152..65_535 do
          {{remote_addr, port}, {local_addr, @port}}
        end

      on_exit(fn ->
        Enum.each(pairs, &Tricep.Application.deregister_socket_pair/1)
      end)

      Enum.each(pairs, fn pair ->
        assert Tricep.Application.register_socket_pair(pair) == :ok
      end)

      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port}) ==
               {:error, :eaddrnotavail}

      refute_receive {:dummy_link_packet, _link, _packet}, 100
    end

    test "connect uses longest-prefix route when exact link is absent", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, routed_addr} = Tricep.Address.from("fd00::abcd")

      on_exit(fn ->
        Tricep.Application.deregister_route(local_addr, 64)
      end)

      :ok = Tricep.Application.register_route(remote_addr, local_addr, 64, 1500)

      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: "fd00::abcd", port: @port})
        end)

      assert_receive {:send, packet}, 1000

      <<6::4, _::4, _::24, _payload_len::16, 6::8, _hop::8, pkt_src::binary-size(16),
        pkt_dst::binary-size(16), tcp_segment::binary>> = packet

      assert pkt_src == remote_addr
      assert pkt_dst == routed_addr
      assert :syn in Tcp.parse_segment(tcp_segment).flags

      Task.shutdown(task, :brutal_kill)
    end

    test "lookup_link prefers the longest matching route prefix", %{
      local_addr: local_addr
    } do
      {:ok, source_48} = Tricep.Address.from("fd00:0:0:1::1")
      {:ok, source_64} = Tricep.Address.from("fd00:0:0:2::1")
      {:ok, prefix_48} = Tricep.Address.from("fd00::")
      {:ok, destination} = Tricep.Address.from("fd00::beef")

      on_exit(fn ->
        Tricep.Application.deregister_route(prefix_48, 48)
        Tricep.Application.deregister_route(local_addr, 64)
      end)

      :ok = Tricep.Application.register_route(source_48, prefix_48, 48, 1400)
      :ok = Tricep.Application.register_route(source_64, local_addr, 64, 1500)

      self = self()
      assert {^self, {^source_64, 1500}} = Tricep.Application.lookup_link(destination)
    end

    test "advertises configured receive buffer size in SYN" do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp, %{recv_buffer_size: 4096})

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      assert_receive {:dummy_link_packet, _link, packet}, 1000

      <<_ip_header::binary-size(40), tcp_segment::binary>> = packet
      parsed = Tcp.parse_segment(tcp_segment)

      assert :syn in parsed.flags
      assert parsed.window == 4096

      Task.shutdown(task, :brutal_kill)
    end

    test "transitions to established on valid SYN-ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      # Wait for SYN
      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

      # Extract the SYN details
      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn_parsed = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      # Build a SYN-ACK response (from local_addr to remote_addr)
      server_seq = 5000

      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          server_seq,
          syn_parsed.seq + 1,
          [:syn, :ack],
          32768
        )

      # Inject the SYN-ACK
      DummyLink.inject_packet(link, syn_ack_segment)

      # Connect should succeed
      assert Task.await(task, 1000) == :ok

      # Should have received the ACK packet
      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000

      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
      ack_parsed = Tcp.parse_segment(ack_segment)

      assert :ack in ack_parsed.flags
      refute :syn in ack_parsed.flags
      assert ack_parsed.ack == server_seq + 1
    end

    test "accepts SYN-ACK that acknowledges wrapped active-open ISS", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      <<src_port::16, _::binary>> = syn_segment

      :sys.replace_state(socket, fn
        {{:syn_sent, from}, state} when is_tuple(from) ->
          {{:syn_sent, from}, %{state | iss: 0xFFFFFFFF, snd_una: 0xFFFFFFFF, snd_nxt: 0}}
      end)

      server_seq = 5000

      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          server_seq,
          0,
          [:syn, :ack],
          32768
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      assert Task.await(task, 1000) == :ok
      assert {:established, %{snd_una: 0, snd_nxt: 0, rcv_nxt: 5001}} = :sys.get_state(socket)

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert :ack in ack.flags
      assert ack.seq == 0
      assert ack.ack == server_seq + 1
    end

    test "returns error on RST response", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      # Wait for SYN
      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      <<src_port::16, _::binary>> = syn_segment

      # Build a RST response
      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          0,
          0,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      # Connect should fail with connection refused
      assert Task.await(task, 1000) == {:error, :econnrefused}
    end

    test "sends RST on bad ACK number", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      # Wait for SYN
      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn_parsed = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      # Build an ACK with wrong ACK number (not SYN-ACK, just ACK)
      bad_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn_parsed.seq + 999,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, bad_ack_segment)

      # Should receive RST
      assert_receive {:dummy_link_packet, _link, rst_packet}, 1000

      <<_ip_header::binary-size(40), rst_segment::binary>> = rst_packet
      rst_parsed = Tcp.parse_segment(rst_segment)

      assert :rst in rst_parsed.flags

      Task.shutdown(task, :brutal_kill)
    end

    test "returns error for unreachable destination" do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      # Try to connect to an address with no registered link
      result = Tricep.connect(socket, %{family: :inet6, addr: "2001:db8::1", port: 80})

      assert result == {:error, :enetunreach}
    end

    test "returns error for invalid address format" do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      # Try to connect with an invalid address
      result = Tricep.connect(socket, %{family: :inet6, addr: "not-an-ip", port: 80})

      assert result == {:error, :einval}
    end

    test "returns error for invalid sockaddr maps without sending SYN" do
      invalid_addresses = [
        %{family: :inet, addr: @local_addr_str, port: @port},
        %{family: :inet6, addr: @local_addr_str},
        %{family: :inet6, addr: @local_addr_str, port: 0},
        %{family: :inet6, addr: @local_addr_str, port: -1},
        %{family: :inet6, addr: @local_addr_str, port: 65_536},
        %{family: :inet6, addr: @local_addr_str, port: "8080"},
        %{family: :inet6, addr: {0x1_0000, 0, 0, 0, 0, 0, 0, 1}, port: @port},
        %{}
      ]

      for address <- invalid_addresses do
        {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

        assert Tricep.connect(socket, address) == {:error, :einval}
        assert Process.alive?(socket)
      end

      refute_receive {:dummy_link_packet, _link, _packet}, 100
    end

    test "ignores malformed segments in SYN_SENT state", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      # Wait for SYN
      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn_parsed = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      # Inject a malformed/truncated segment (too short to parse)
      DummyLink.inject_packet(link, <<1, 2, 3>>)

      # Socket should still be waiting - send proper SYN-ACK
      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn_parsed.seq + 1,
          [:syn, :ack],
          32768
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      # Should succeed
      assert Task.await(task, 1000) == :ok
    end

    test "returns error when already connected", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      # Wait for SYN
      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn_parsed = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      # Send SYN-ACK
      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn_parsed.seq + 1,
          [:syn, :ack],
          32768
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      # First connect succeeds
      assert Task.await(task, 1000) == :ok

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Second connect should fail
      result = Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
      assert result == {:error, :eisconn}
    end

    test "ignores non-SYN-ACK packets while in SYN_SENT", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      # Wait for SYN
      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn_parsed = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      # Send a SYN-only packet (should be ignored, we need SYN+ACK)
      syn_only =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          1000,
          0,
          [:syn],
          32768
        )

      DummyLink.inject_packet(link, syn_only)

      # Socket should still be waiting - send proper SYN-ACK
      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn_parsed.seq + 1,
          [:syn, :ack],
          32768
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      # Should succeed
      assert Task.await(task, 1000) == :ok
    end
  end

  describe "handle_packet/3" do
    test "routes packet to correct socket", %{local_addr: local_addr, remote_addr: remote_addr} do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      # Wait for SYN
      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn_parsed = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      # Use handle_packet directly to route a SYN-ACK
      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn_parsed.seq + 1,
          [:syn, :ack],
          32768
        )

      # Call handle_packet directly (simulating what DummyLink.inject_packet does)
      :ok = Tricep.Socket.handle_packet(local_addr, remote_addr, syn_ack_segment)

      assert Task.await(task, 1000) == :ok
    end

    test "sends RST+ACK for SYN to closed port", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      client_port = 40_030
      client_seq = 1234

      syn =
        Tcp.build_segment(
          {{local_addr, client_port}, {remote_addr, @port}},
          client_seq,
          0,
          [:syn],
          32768
        )

      DummyLink.inject_packet(link, syn)

      assert_receive {:dummy_link_packet, _link, packet}, 1000

      <<6::4, _::4, _::24, _payload_len::16, 6::8, _hop::8, pkt_src::binary-size(16),
        pkt_dst::binary-size(16), rst_segment::binary>> = packet

      rst = Tcp.parse_segment(rst_segment)

      assert pkt_src == remote_addr
      assert pkt_dst == local_addr
      assert :rst in rst.flags
      assert :ack in rst.flags
      assert rst.seq == 0
      assert rst.ack == client_seq + 1
    end

    test "sends bare RST for ACK to closed port", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      client_port = 40_031
      peer_ack = 9000

      ack =
        Tcp.build_segment(
          {{local_addr, client_port}, {remote_addr, @port}},
          1234,
          peer_ack,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack)

      assert_receive {:dummy_link_packet, _link, packet}, 1000
      <<_ip_header::binary-size(40), rst_segment::binary>> = packet
      rst = Tcp.parse_segment(rst_segment)

      assert :rst in rst.flags
      refute :ack in rst.flags
      assert rst.seq == peer_ack
      assert rst.ack == 0
    end

    test "does not send RST in response to RST for closed port", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      rst =
        Tcp.build_segment(
          {{local_addr, 40_032}, {remote_addr, @port}},
          1234,
          0,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst)

      refute_receive {:dummy_link_packet, _link, _packet}, 100
    end
  end

  describe "listen/2 and accept/2" do
    test "accepts inbound TCP handshake and returns established socket", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(listener, %{family: :inet6, addr: @remote_addr_str, port: @port}) == :ok
      assert Tricep.listen(listener, 2) == :ok

      accept_task = Task.async(fn -> Tricep.accept(listener, 1000) end)

      client_port = 40_000
      client_seq = 1000
      syn_ack = send_passive_syn(link, local_addr, remote_addr, client_port, client_seq)

      send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, syn_ack.seq)

      assert {:ok, accepted} = Task.await(accept_task, 1000)
      on_exit(fn -> stop_socket(accepted) end)

      assert {:established, state} = :sys.get_state(accepted)
      assert state.pair == {{remote_addr, @port}, {local_addr, client_port}}
      assert state.snd_mss == 1000

      assert Tricep.send(accepted, "ok") == :ok
      assert_receive {:dummy_link_packet, _link, data_packet}, 1000

      <<6::4, _::4, _::24, _payload_len::16, 6::8, _hop::8, pkt_src::binary-size(16),
        pkt_dst::binary-size(16), tcp_segment::binary>> = data_packet

      parsed = Tcp.parse_segment(tcp_segment)

      assert pkt_src == remote_addr
      assert pkt_dst == local_addr
      assert parsed.seq == syn_ack.seq + 1
      assert parsed.ack == client_seq + 1
      assert parsed.payload == "ok"

      assert Tricep.close(listener) == :ok
    end

    test "accept with nowait notifies when a connection is queued", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(listener, %{family: :inet6, addr: @remote_addr_str, port: @port}) == :ok
      assert Tricep.listen(listener, 2) == :ok

      assert {:select, {:select_info, :accept, ref}} = Tricep.accept(listener, :nowait)

      client_port = 40_001
      client_seq = 2000
      syn_ack = send_passive_syn(link, local_addr, remote_addr, client_port, client_seq)
      send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, syn_ack.seq)

      assert_receive {:"$socket", ^listener, :select, ^ref}, 1000
      assert {:ok, accepted} = Tricep.accept(listener, :nowait)
      on_exit(fn -> stop_socket(accepted) end)

      assert {:established, state} = :sys.get_state(accepted)
      assert state.pair == {{remote_addr, @port}, {local_addr, client_port}}

      assert Tricep.close(listener) == :ok
    end

    test "listen backlog drops additional SYNs while full", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(listener, %{family: :inet6, addr: @remote_addr_str, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      send_passive_syn(link, local_addr, remote_addr, 40_002, 3000)

      syn =
        Tcp.build_segment(
          {{local_addr, 40_003}, {remote_addr, @port}},
          4000,
          0,
          [:syn],
          32768
        )

      DummyLink.inject_packet(link, syn)
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      assert Tricep.close(listener) == :ok
    end

    test "bind rejects duplicate local address and port" do
      {:ok, listener1} = Tricep.open(:inet6, :stream, :tcp)
      {:ok, listener2} = Tricep.open(:inet6, :stream, :tcp)

      address = %{family: :inet6, addr: @remote_addr_str, port: @port}

      assert Tricep.bind(listener1, address) == :ok
      assert Tricep.bind(listener2, address) == {:error, :eaddrinuse}

      assert Tricep.close(listener1) == :ok
    end

    test "bind rejects specific address when wildcard address owns the port" do
      {:ok, wildcard} = Tricep.open(:inet6, :stream, :tcp)
      {:ok, specific} = Tricep.open(:inet6, :stream, :tcp)

      port = @port + 2

      assert Tricep.bind(wildcard, %{family: :inet6, addr: "::", port: port}) == :ok

      assert Tricep.bind(specific, %{family: :inet6, addr: @remote_addr_str, port: port}) ==
               {:error, :eaddrinuse}

      assert Tricep.close(wildcard) == :ok
    end

    test "bind rejects wildcard address when a specific address owns the port" do
      {:ok, specific} = Tricep.open(:inet6, :stream, :tcp)
      {:ok, wildcard} = Tricep.open(:inet6, :stream, :tcp)

      port = @port + 3

      assert Tricep.bind(specific, %{family: :inet6, addr: @remote_addr_str, port: port}) == :ok

      assert Tricep.bind(wildcard, %{family: :inet6, addr: "::", port: port}) ==
               {:error, :eaddrinuse}

      assert Tricep.close(specific) == :ok
    end

    test "bind with port zero assigns an ephemeral local port", %{remote_addr: remote_addr} do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(socket, %{family: :inet6, addr: remote_addr, port: 0}) == :ok

      assert {:ok, %{family: :inet6, addr: {0xFD00, 0, 0, 0, 0, 0, 0, 2}, port: port}} =
               Tricep.sockname(socket)

      assert port in 49_152..65_535

      assert Tricep.close(socket) == :ok
    end

    test "bind with port zero reserves the selected local port", %{remote_addr: remote_addr} do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)
      {:ok, duplicate} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(socket, %{family: :inet6, addr: remote_addr, port: 0}) == :ok
      assert {:ok, %{port: port}} = Tricep.sockname(socket)

      assert Tricep.bind(duplicate, %{family: :inet6, addr: remote_addr, port: port}) ==
               {:error, :eaddrinuse}

      assert Tricep.close(socket) == :ok
    end

    test "sockname on an unbound socket returns error" do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.sockname(socket) == {:error, :einval}
    end

    test "bind accepts a raw 16-byte IPv6 address binary", %{remote_addr: remote_addr} do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(socket, %{family: :inet6, addr: remote_addr, port: @port + 1}) == :ok
      assert Process.alive?(socket)

      assert Tricep.close(socket) == :ok
    end
  end

  describe "receive checksum validation" do
    test "drops invalid checksum SYN-ACK without completing connect", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn_parsed = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn_parsed.seq + 1,
          [:syn, :ack],
          32768
        )

      DummyLink.inject_packet(link, corrupt_checksum(syn_ack_segment))

      refute Task.yield(task, 100)
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      DummyLink.inject_packet(link, syn_ack_segment)

      assert Task.await(task, 1000) == :ok
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000
    end

    test "drops invalid checksum data without buffering or ACKing it", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.rcv_nxt,
          state.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "corrupt data"
        )

      DummyLink.inject_packet(link, corrupt_checksum(data_segment))
      refute_receive {:dummy_link_packet, _link, _packet}, 100
      assert Tricep.recv(socket, 0, 20) == {:error, :timeout}

      {:established, after_state} = :sys.get_state(socket)
      assert after_state.rcv_nxt == state.rcv_nxt
      assert after_state.recv_buffer == <<>>
    end

    test "drops invalid checksum ACK without advancing send state", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000
      assert Tricep.send(socket, "abc") == :ok
      assert_receive {:dummy_link_packet, _link, _data_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair
      assert state.unacked_segments != []

      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.rcv_nxt,
          state.snd_nxt,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, corrupt_checksum(ack_segment))

      {:established, after_state} = :sys.get_state(socket)
      assert after_state.snd_una == state.snd_una
      assert after_state.unacked_segments == state.unacked_segments
    end

    test "drops invalid checksum RST without closing the socket", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          0,
          0,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, corrupt_checksum(rst_segment))

      {:established, after_state} = :sys.get_state(socket)
      assert after_state == state
    end
  end

  describe "MSS option" do
    test "SYN packet includes MSS option" do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      # Wait for the SYN packet
      assert_receive {:dummy_link_packet, _link, packet}, 1000

      <<_ip_header::binary-size(40), tcp_segment::binary>> = packet
      parsed = Tcp.parse_segment(tcp_segment)

      # Should have MSS option set to default (1220 for IPv6)
      assert parsed.options.mss == 1440

      Task.shutdown(task, :brutal_kill)
    end

    test "stores peer MSS from SYN-ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      # Wait for SYN
      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn_parsed = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      # Send SYN-ACK with MSS option
      peer_mss = 1460

      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn_parsed.seq + 1,
          [:syn, :ack],
          32768,
          mss: peer_mss
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      assert Task.await(task, 1000) == :ok

      # Check that the socket stored the peer's MSS
      # gen_statem returns {state_name, state_data}
      {:established, state} = :sys.get_state(socket)
      assert state.snd_mss == peer_mss
      assert state.rcv_mss == 1440
    end

    test "defaults to 1440 MSS when peer doesn't send MSS option", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      # Wait for SYN
      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn_parsed = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      # Send SYN-ACK WITHOUT MSS option
      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn_parsed.seq + 1,
          [:syn, :ack],
          32768
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      assert Task.await(task, 1000) == :ok

      # Check that the socket defaulted to 1220 (IPv6 min MTU 1280 - 60 headers)
      # gen_statem returns {state_name, state_data}
      {:established, state} = :sys.get_state(socket)
      assert state.snd_mss == 1220
    end

    test "SYN advertises window scale for large receive buffers" do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp, %{recv_buffer_size: 1_000_000})

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      assert_receive {:dummy_link_packet, _link, packet}, 1000

      <<_ip_header::binary-size(40), tcp_segment::binary>> = packet
      parsed = Tcp.parse_segment(tcp_segment)

      assert parsed.options.window_scale == 4
      assert parsed.window == 62_500

      Task.shutdown(task, :brutal_kill)
    end

    test "stores peer window scale from SYN-ACK without unsupported metadata", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn_parsed = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn_parsed.seq + 1,
          [:syn, :ack],
          10,
          window_scale: 4,
          sack_permitted: true,
          timestamp: {123, 456}
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      assert Task.await(task, 1000) == :ok

      {:established, state} = :sys.get_state(socket)

      assert state.snd_wnd_scale == 4
      assert state.snd_wnd == 160
      refute Map.has_key?(state, :peer_sack_permitted)
      refute Map.has_key?(state, :peer_timestamp)
    end

    test "passive open advertises and stores negotiated window scale", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp, %{recv_buffer_size: 1_000_000})

      assert Tricep.bind(listener, %{family: :inet6, addr: @remote_addr_str, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      client_port = 40_010
      client_seq = 9000

      syn =
        Tcp.build_segment(
          {{local_addr, client_port}, {remote_addr, @port}},
          client_seq,
          0,
          [:syn],
          10,
          mss: 1000,
          window_scale: 3,
          sack_permitted: true,
          timestamp: {321, 654}
        )

      DummyLink.inject_packet(link, syn)

      assert_receive {:dummy_link_packet, _link, syn_ack_packet}, 1000

      <<_ip_header::binary-size(40), syn_ack_segment::binary>> = syn_ack_packet
      syn_ack = Tcp.parse_segment(syn_ack_segment)

      assert syn_ack.options.window_scale == 4
      assert syn_ack.window == 62_500

      send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, syn_ack.seq)

      assert {:ok, accepted} = Tricep.accept(listener, 1000)
      on_exit(fn -> stop_socket(accepted) end)

      {:established, state} = :sys.get_state(accepted)

      assert state.snd_wnd_scale == 3
      assert state.snd_wnd == 262_144
      refute Map.has_key?(state, :peer_sack_permitted)
      refute Map.has_key?(state, :peer_timestamp)

      assert Tricep.close(listener) == :ok
    end
  end

  describe "send/2" do
    test "sends data segment with correct seq and ack", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Send data
      assert Tricep.send(socket, "Hello") == :ok

      # Should receive data segment
      assert_receive {:dummy_link_packet, _link, data_packet}, 1000

      <<_ip_header::binary-size(40), data_segment::binary>> = data_packet
      parsed = Tcp.parse_segment(data_segment)

      assert parsed.payload == "Hello"
      assert :ack in parsed.flags
      assert :psh in parsed.flags
    end

    test "empty send returns immediately without waiting for peer window", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 0)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.send(socket, "", :nowait) == :ok
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      {:established, state} = :sys.get_state(socket)
      assert state.send_waiters == []
      assert Tricep.DataBuffer.empty?(state.send_buffer)
    end

    test "returns {:error, :einval} for negative send timeout", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.send(socket, "Hello", -1) == {:error, :einval}
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      {:established, state} = :sys.get_state(socket)
      assert Tricep.DataBuffer.empty?(state.send_buffer)
      assert state.send_waiters == []
    end

    test "segments large data at MSS boundary", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, mss: 10)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Send data larger than MSS
      assert Tricep.send(socket, "Hello, World!") == :ok

      # Should receive two segments
      assert_receive {:dummy_link_packet, _link, packet1}, 1000
      assert_receive {:dummy_link_packet, _link, packet2}, 1000

      <<_::binary-size(40), seg1::binary>> = packet1
      <<_::binary-size(40), seg2::binary>> = packet2

      parsed1 = Tcp.parse_segment(seg1)
      parsed2 = Tcp.parse_segment(seg2)

      assert parsed1.payload == "Hello, Wor"
      assert parsed2.payload == "ld!"
    end

    test "limits sent data to the peer receive window and resumes after ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, mss: 10, window: 1)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.send(socket, "abc") == :ok

      assert_receive {:dummy_link_packet, _link, packet1}, 1000
      <<_::binary-size(40), seg1::binary>> = packet1
      parsed1 = Tcp.parse_segment(seg1)

      assert parsed1.payload == "a"
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair
      assert Tricep.DataBuffer.size(state.send_buffer) == 2

      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          wrap_seq(parsed1.seq + byte_size(parsed1.payload)),
          [:ack],
          2
        )

      DummyLink.inject_packet(link, ack_segment)

      assert_receive {:dummy_link_packet, _link, packet2}, 1000
      <<_::binary-size(40), seg2::binary>> = packet2
      parsed2 = Tcp.parse_segment(seg2)

      assert parsed2.payload == "bc"

      {:established, state} = :sys.get_state(socket)
      assert Tricep.DataBuffer.empty?(state.send_buffer)
    end

    test "nowait send waits when the peer receive window is zero", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 0)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert {:select, {:select_info, :send, ref}} = Tricep.send(socket, "abc", :nowait)
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      window_update =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:ack],
          3
        )

      DummyLink.inject_packet(link, window_update)

      assert_receive {:"$socket", ^socket, :select, ^ref}, 1000
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      assert Tricep.send(socket, "abc", :nowait) == :ok
      assert_receive {:dummy_link_packet, _link, packet}, 1000

      <<_::binary-size(40), segment::binary>> = packet
      parsed = Tcp.parse_segment(segment)
      assert parsed.payload == "abc"
      refute_receive {:dummy_link_packet, _link, _packet}, 100
    end

    test "returns error when not connected" do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)
      assert Tricep.send(socket, "Hello") == {:error, :enotconn}
    end
  end

  describe "recv/2" do
    test "receives buffered data", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get socket state to find src_port
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Inject data from peer
      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "Hello from peer"
        )

      DummyLink.inject_packet(link, data_segment)

      # Should be able to recv the data
      assert Tricep.recv(socket, 0, 1000) == {:ok, "Hello from peer"}

      # Should have sent an ACK
      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_::binary-size(40), ack_seg::binary>> = ack_packet
      ack_parsed = Tcp.parse_segment(ack_seg)
      assert :ack in ack_parsed.flags
      assert ack_parsed.ack == state.irs + 1 + byte_size("Hello from peer")
    end

    test "advertised receive window shrinks with buffered data and reopens on recv", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket =
        establish_connection(link, local_addr, remote_addr, open_opts: %{recv_buffer_size: 10})

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "abcdef"
        )

      DummyLink.inject_packet(link, data_segment)

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_::binary-size(40), ack_segment::binary>> = ack_packet
      ack_parsed = Tcp.parse_segment(ack_segment)

      assert ack_parsed.ack == state.irs + 1 + byte_size("abcdef")
      assert ack_parsed.window == 4

      {:established, buffered_state} = :sys.get_state(socket)
      assert buffered_state.rcv_wnd == 4
      assert buffered_state.recv_buffer == "abcdef"

      assert Tricep.recv(socket, 3, 1000) == {:ok, "abc"}

      assert_receive {:dummy_link_packet, _link, update_packet}, 1000
      <<_::binary-size(40), update_segment::binary>> = update_packet
      update_parsed = Tcp.parse_segment(update_segment)

      assert update_parsed.ack == ack_parsed.ack
      assert update_parsed.window == 7

      {:established, reopened_state} = :sys.get_state(socket)
      assert reopened_state.rcv_wnd == 7
      assert reopened_state.recv_buffer == "def"
    end

    test "receive buffer caps accepted payload to advertised window", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket =
        establish_connection(link, local_addr, remote_addr, open_opts: %{recv_buffer_size: 5})

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "123456789"
        )

      DummyLink.inject_packet(link, data_segment)

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_::binary-size(40), ack_segment::binary>> = ack_packet
      ack_parsed = Tcp.parse_segment(ack_segment)

      assert ack_parsed.ack == state.irs + 1 + 5
      assert ack_parsed.window == 0

      {:established, buffered_state} = :sys.get_state(socket)
      assert buffered_state.recv_buffer == "12345"
      assert buffered_state.rcv_nxt == state.irs + 1 + 5
      assert buffered_state.rcv_wnd == 0
    end

    test "blocks until data arrives", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get socket state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Start recv in a task (will block)
      recv_task = Task.async(fn -> Tricep.recv(socket, 0, 5000) end)

      wait_for_recv_waiters(socket)

      # Inject data
      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "Delayed data"
        )

      DummyLink.inject_packet(link, data_segment)

      # Recv should complete with the data
      assert Task.await(recv_task, 1000) == {:ok, "Delayed data"}
    end

    test "returns error when not connected" do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)
      assert Tricep.recv(socket, 0, 100) == {:error, :enotconn}
    end

    test "times out and removes waiter from list", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Recv with short timeout
      result = Tricep.recv(socket, 0, 100)
      assert result == {:error, :timeout}

      # Socket should still be usable - verify waiters list is empty
      {:established, state} = :sys.get_state(socket)
      assert state.recv_waiters == []
    end

    test "recv with specific length waits for enough data", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get socket state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Start recv asking for 20 bytes
      recv_task = Task.async(fn -> Tricep.recv(socket, 20, 5000) end)

      wait_for_recv_waiters(socket)

      # Inject only 10 bytes - should still be waiting
      data_segment1 =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "1234567890"
        )

      DummyLink.inject_packet(link, data_segment1)

      # Wait for ACK
      assert_receive {:dummy_link_packet, _link, _ack1}, 1000

      # Task should still be waiting
      refute Task.yield(recv_task, 0)

      # Inject another 10 bytes
      data_segment2 =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1 + 10,
          state.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "ABCDEFGHIJ"
        )

      DummyLink.inject_packet(link, data_segment2)

      # Now should get exactly 20 bytes
      assert Task.await(recv_task, 1000) == {:ok, "1234567890ABCDEFGHIJ"}
    end
  end

  describe "recv edge cases" do
    test "recv returns immediately when data already buffered", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get socket state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Inject data first
      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "Pre-buffered data"
        )

      DummyLink.inject_packet(link, data_segment)

      # Drain the ACK
      assert_receive {:dummy_link_packet, _link, _ack}, 1000

      # Now recv should return immediately (data already buffered)
      assert Tricep.recv(socket, 0, 1000) == {:ok, "Pre-buffered data"}
    end

    test "negative recv length returns {:error, :einval} without consuming buffered data", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "buffered"
        )

      DummyLink.inject_packet(link, data_segment)

      # Drain the ACK
      assert_receive {:dummy_link_packet, _link, _ack}, 1000

      assert Tricep.recv(socket, -1, 1000) == {:error, :einval}
      assert Process.alive?(socket)
      assert Tricep.recv(socket, 0, 1000) == {:ok, "buffered"}
    end

    test "negative recv timeout returns {:error, :einval} without adding a waiter", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.recv(socket, 0, -1) == {:error, :einval}

      {:established, state} = :sys.get_state(socket)
      assert state.recv_waiters == []
      assert state.recv_selects == []
    end

    test "recv timeout is canceled after data arrives", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get socket state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Start recv with a longer timeout
      recv_task = Task.async(fn -> Tricep.recv(socket, 0, 500) end)

      wait_for_recv_waiters(socket)

      # Inject data - this should satisfy the waiter and remove it
      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "Data arrived"
        )

      DummyLink.inject_packet(link, data_segment)

      # recv should complete with data
      assert Task.await(recv_task, 1000) == {:ok, "Data arrived"}

      {:established, state} = :sys.get_state(socket)
      assert state.recv_waiters == []
    end
  end

  describe "established state edge cases" do
    test "RST notifies waiting receivers", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get socket state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Start recv in a task (will block waiting for data)
      recv_task = Task.async(fn -> Tricep.recv(socket, 0, 5000) end)

      wait_for_recv_waiters(socket)

      # Inject RST
      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      # Recv should return error
      assert Task.await(recv_task, 1000) == {:error, :econnreset}
    end

    test "RST with old sequence is rejected with challenge ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.rcv_nxt - 1),
          state.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert :ack in ack.flags
      assert ack.ack == state.rcv_nxt
      {:established, _state} = :sys.get_state(socket)
    end

    test "RST outside future receive window is rejected with challenge ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.rcv_nxt + state.rcv_wnd + 1),
          state.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert :ack in ack.flags
      assert ack.ack == state.rcv_nxt
      {:established, _state} = :sys.get_state(socket)
    end

    test "RST notifies blocking send waiters", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 0)

      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      send_task = Task.async(fn -> Tricep.send(socket, "blocked", :infinity) end)
      wait_for_send_waiters(socket)

      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      assert Task.await(send_task, 1000) == {:error, :econnreset}
      {:closed, nil} = :sys.get_state(socket)
    end

    test "RST cancels timed send waiters", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 0)

      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      send_task = Task.async(fn -> Tricep.send(socket, "blocked", 5_000) end)
      wait_for_send_waiters(socket)

      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      assert Task.await(send_task, 1000) == {:error, :econnreset}
      {:closed, nil} = :sys.get_state(socket)

      refute_receive {:EXIT, _pid, _reason}, 100
    end

    test "RST notifies nowait send waiters", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 0)

      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      assert {:select, {:select_info, :send, ref}} = Tricep.send(socket, "blocked", :nowait)

      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      assert_receive {:"$socket", ^socket, :select, ^ref}, 1000
      assert Tricep.send(socket, "blocked", :nowait) == {:error, :enotconn}
    end

    test "pure ACK updates send window", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get initial state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair
      initial_snd_wnd = state.snd_wnd

      # Inject a pure ACK with different window
      new_window = 65535

      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:ack],
          new_window
        )

      DummyLink.inject_packet(link, ack_segment)

      # Check window was updated
      {:established, new_state} = :sys.get_state(socket)
      assert new_state.snd_wnd == new_window
      assert new_state.snd_wnd != initial_snd_wnd or initial_snd_wnd == new_window
    end

    test "off-window pure ACK does not update send state", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.send(socket, "Hello") == :ok
      assert_receive {:dummy_link_packet, _link, _data_packet}, 1000

      {:established, state_before_ack} = :sys.get_state(socket)
      {{_, src_port}, _} = state_before_ack.pair

      off_window_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state_before_ack.rcv_nxt - 1),
          state_before_ack.snd_nxt,
          [:ack],
          65_535
        )

      DummyLink.inject_packet(link, off_window_ack)

      assert_receive {:dummy_link_packet, _link, challenge_packet}, 1000
      <<_ip_header::binary-size(40), challenge_segment::binary>> = challenge_packet
      challenge = Tcp.parse_segment(challenge_segment)

      assert :ack in challenge.flags
      assert challenge.seq == state_before_ack.snd_nxt
      assert challenge.ack == state_before_ack.rcv_nxt

      {:established, state_after_ack} = :sys.get_state(socket)

      assert state_after_ack.snd_una == state_before_ack.snd_una
      assert state_after_ack.snd_wnd == state_before_ack.snd_wnd
      assert state_after_ack.unacked_segments == state_before_ack.unacked_segments
      assert state_after_ack.rto_timer_active == state_before_ack.rto_timer_active
    end

    test "buffers out of order packets until the gap arrives", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get socket state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      out_of_order_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.rcv_nxt + 5,
          state.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "world"
        )

      DummyLink.inject_packet(link, out_of_order_segment)

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert :ack in ack.flags
      assert ack.ack == state.rcv_nxt

      assert Tricep.recv(socket, 0, 100) == {:error, :timeout}

      {:established, queued_state} = :sys.get_state(socket)
      assert queued_state.rcv_nxt == state.rcv_nxt
      assert [{seq, seq_end, payload}] = queued_state.out_of_order_segments
      assert seq == state.rcv_nxt + 5
      assert seq_end == state.rcv_nxt + 10
      assert payload == "world"

      gap_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.rcv_nxt,
          state.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "hello"
        )

      DummyLink.inject_packet(link, gap_segment)

      assert_receive {:dummy_link_packet, _link, final_ack_packet}, 1000
      <<_ip_header::binary-size(40), final_ack_segment::binary>> = final_ack_packet
      final_ack = Tcp.parse_segment(final_ack_segment)

      assert :ack in final_ack.flags
      assert final_ack.ack == state.rcv_nxt + 10

      assert Tricep.recv(socket, 10, 1000) == {:ok, "helloworld"}

      {:established, new_state} = :sys.get_state(socket)
      assert new_state.out_of_order_segments == []
    end

    test "ACKs duplicate data without duplicate delivery", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "duplicate once"
        )

      DummyLink.inject_packet(link, data_segment)

      assert_receive {:dummy_link_packet, _link, first_ack_packet}, 1000
      <<_ip_header::binary-size(40), first_ack_segment::binary>> = first_ack_packet
      first_ack = Tcp.parse_segment(first_ack_segment)

      DummyLink.inject_packet(link, data_segment)

      assert_receive {:dummy_link_packet, _link, duplicate_ack_packet}, 1000
      <<_ip_header::binary-size(40), duplicate_ack_segment::binary>> = duplicate_ack_packet
      duplicate_ack = Tcp.parse_segment(duplicate_ack_segment)

      assert duplicate_ack.ack == first_ack.ack
      assert Tricep.recv(socket, 0, 1000) == {:ok, "duplicate once"}
    end

    test "rejects data when ACK is beyond snd_nxt", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      invalid_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          wrap_seq(state.snd_nxt + 1),
          [:ack, :psh],
          32768,
          payload: "must not deliver"
        )

      DummyLink.inject_packet(link, invalid_ack_segment)

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert :ack in ack.flags
      assert ack.seq == state.snd_nxt
      assert ack.ack == state.rcv_nxt
      assert Tricep.recv(socket, 0, 100) == {:error, :timeout}

      {:established, new_state} = :sys.get_state(socket)
      assert new_state.rcv_nxt == state.rcv_nxt
      assert new_state.recv_buffer == <<>>
    end

    test "ignores malformed segments in established state", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get socket state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Inject malformed segment (too short to parse)
      DummyLink.inject_packet(link, <<1, 2, 3>>)

      # Socket should still be in established state and usable
      {:established, new_state} = :sys.get_state(socket)
      assert new_state.rcv_nxt == state.rcv_nxt

      # Can still recv properly formatted data
      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "Valid data"
        )

      DummyLink.inject_packet(link, data_segment)
      assert Tricep.recv(socket, 0, 1000) == {:ok, "Valid data"}
    end
  end

  describe "close/1" do
    test "active close sends FIN and returns immediately", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Close should return immediately
      assert Tricep.close(socket) == :ok

      # Should receive FIN packet
      assert_receive {:dummy_link_packet, _link, fin_packet}, 1000

      <<_ip_header::binary-size(40), fin_segment::binary>> = fin_packet
      parsed = Tcp.parse_segment(fin_segment)

      assert :fin in parsed.flags
      assert :ack in parsed.flags
    end

    test "active close releases blocking recv waiters", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      recv_task = Task.async(fn -> Tricep.recv(socket, 0, :infinity) end)
      wait_for_recv_waiters(socket)

      assert Tricep.close(socket) == :ok
      assert Task.await(recv_task, 1000) == {:ok, <<>>}

      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      {:fin_wait_1, state} = :sys.get_state(socket)
      assert state.recv_waiters == []
      assert state.recv_selects == []
    end

    test "active close releases blocking send waiters", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 0)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      send_task = Task.async(fn -> Tricep.send(socket, "blocked", 5_000) end)
      wait_for_send_waiters(socket)

      {:established, state} = :sys.get_state(socket)
      assert state.persist_timer_active

      assert Tricep.close(socket) == :ok
      assert Task.await(send_task, 1000) == {:error, :epipe}

      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      {:fin_wait_1, state} = :sys.get_state(socket)
      assert state.send_waiters == []
      refute state.persist_timer_active
    end

    test "active close drains queued send buffer before FIN", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, mss: 10, window: 1)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.send(socket, "abc") == :ok

      assert_receive {:dummy_link_packet, _link, packet1}, 1000
      <<_ip_header::binary-size(40), segment1::binary>> = packet1
      parsed1 = Tcp.parse_segment(segment1)
      assert parsed1.payload == "a"

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair
      assert Tricep.DataBuffer.size(state.send_buffer) == 2

      assert Tricep.close(socket) == :ok
      assert Tricep.send(socket, "after close") == {:error, :epipe}
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          wrap_seq(parsed1.seq + byte_size(parsed1.payload)),
          [:ack],
          2
        )

      DummyLink.inject_packet(link, ack_segment)

      assert_receive {:dummy_link_packet, _link, packet2}, 1000
      <<_ip_header::binary-size(40), segment2::binary>> = packet2
      parsed2 = Tcp.parse_segment(segment2)
      assert parsed2.payload == "bc"

      assert_receive {:dummy_link_packet, _link, fin_packet}, 1000
      <<_ip_header::binary-size(40), fin_segment::binary>> = fin_packet
      fin = Tcp.parse_segment(fin_segment)

      assert :fin in fin.flags
      assert fin.seq == wrap_seq(parsed2.seq + byte_size(parsed2.payload))
      assert fin.payload == <<>>

      {:fin_wait_1, fin_wait_state} = :sys.get_state(socket)
      assert Tricep.DataBuffer.empty?(fin_wait_state.send_buffer)
    end

    test "active close transitions through FIN_WAIT states", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state before close
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Close
      assert Tricep.close(socket) == :ok

      # Drain FIN
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      # Should be in FIN_WAIT_1
      {:fin_wait_1, _} = :sys.get_state(socket)

      # Send ACK of our FIN
      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      # Should be in FIN_WAIT_2
      {:fin_wait_2, _} = :sys.get_state(socket)

      # Send FIN from peer
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      # Should be in TIME_WAIT
      {:time_wait, _} = :sys.get_state(socket)

      # Should receive ACK for peer's FIN
      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_::binary-size(40), ack_seg::binary>> = ack_packet
      ack_parsed = Tcp.parse_segment(ack_seg)
      assert :ack in ack_parsed.flags
    end

    test "passive close receives FIN and returns EOF on recv", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Send FIN from peer
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      # Should be in CLOSE_WAIT
      {:close_wait, _} = :sys.get_state(socket)

      # Should receive ACK for FIN
      assert_receive {:dummy_link_packet, _link, _ack_packet2}, 1000

      # recv should return EOF
      assert Tricep.recv(socket, 0, 100) == {:ok, <<>>}
    end

    test "passive close rejects ACK beyond snd_nxt before accepting FIN", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          wrap_seq(state.snd_nxt + 1),
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:established, new_state} = :sys.get_state(socket)

      assert new_state.snd_una == state.snd_una
      assert new_state.snd_nxt == state.snd_nxt
      assert new_state.rcv_nxt == state.rcv_nxt
      assert new_state.fin_received == false

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert :ack in ack.flags
      assert ack.seq == state.snd_nxt
      assert ack.ack == state.rcv_nxt
    end

    test "recv returns buffered data then EOF after receiving FIN", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Send data with FIN
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768,
          payload: "Final data"
        )

      DummyLink.inject_packet(link, fin_segment)

      # First recv gets the data
      assert Tricep.recv(socket, 0, 100) == {:ok, "Final data"}

      # Second recv gets EOF
      assert Tricep.recv(socket, 0, 100) == {:ok, <<>>}
    end

    test "close on non-established socket returns error" do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)
      assert Tricep.close(socket) == {:error, :enotconn}
    end

    test "send after close returns error", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Close
      assert Tricep.close(socket) == :ok

      # Drain FIN
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      # send should fail with epipe (connection closing)
      assert Tricep.send(socket, "data") == {:error, :epipe}
    end

    test "close with pending recv waiter delivers EOF", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Start recv in background
      recv_task = Task.async(fn -> Tricep.recv(socket, 0, 5000) end)

      wait_for_recv_waiters(socket)

      # Send FIN from peer
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      # recv should return EOF
      assert Task.await(recv_task, 1000) == {:ok, <<>>}
    end
  end

  describe "FIN_WAIT_1 state" do
    test "RST in FIN_WAIT_1 closes connection", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Close to enter FIN_WAIT_1
      assert Tricep.close(socket) == :ok

      # Drain FIN
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      # Should be in FIN_WAIT_1
      {:fin_wait_1, _} = :sys.get_state(socket)

      # Send RST
      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      # Should be closed
      {:closed, nil} = :sys.get_state(socket)
    end

    test "FIN+ACK in FIN_WAIT_1 goes directly to TIME_WAIT", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Close to enter FIN_WAIT_1
      assert Tricep.close(socket) == :ok

      # Drain FIN
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      {:fin_wait_1, _} = :sys.get_state(socket)

      # Send FIN+ACK (acknowledging our FIN and sending their FIN)
      fin_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_ack_segment)

      # Should go directly to TIME_WAIT (skipping FIN_WAIT_2)
      {:time_wait, _} = :sys.get_state(socket)

      # Should have sent ACK for peer's FIN
      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_::binary-size(40), ack_seg::binary>> = ack_packet
      assert :ack in Tcp.parse_segment(ack_seg).flags
    end

    test "simultaneous close (FIN without ACK) goes to CLOSING", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Close to enter FIN_WAIT_1
      assert Tricep.close(socket) == :ok

      # Drain FIN
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      {:fin_wait_1, _} = :sys.get_state(socket)

      # Send FIN without ACK of our FIN (simultaneous close - they didn't see our FIN yet)
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      # Should go to CLOSING (simultaneous close)
      {:closing, _} = :sys.get_state(socket)

      # Should have sent ACK for peer's FIN
      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_::binary-size(40), ack_seg::binary>> = ack_packet
      assert :ack in Tcp.parse_segment(ack_seg).flags
    end

    test "ignores malformed segment in FIN_WAIT_1", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Close to enter FIN_WAIT_1
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      {:fin_wait_1, _} = :sys.get_state(socket)

      # Inject malformed segment
      DummyLink.inject_packet(link, <<1, 2, 3>>)

      # Should still be in FIN_WAIT_1
      {:fin_wait_1, _} = :sys.get_state(socket)

      # Now send proper ACK
      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      # Should transition to FIN_WAIT_2
      {:fin_wait_2, _} = :sys.get_state(socket)
    end

    test "ignores unexpected segment in FIN_WAIT_1", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Close to enter FIN_WAIT_1
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      {:fin_wait_1, _} = :sys.get_state(socket)

      # Send ACK with wrong ack number (not ACKing our FIN)
      wrong_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, wrong_ack)

      # Should still be in FIN_WAIT_1 (wrong ACK ignored)
      {:fin_wait_1, _} = :sys.get_state(socket)
    end

    test "retransmits lost FIN in FIN_WAIT_1", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.close(socket) == :ok

      assert_receive {:dummy_link_packet, _link, fin_packet1}, 1000
      <<_ip_header::binary-size(40), fin_segment1::binary>> = fin_packet1
      parsed1 = Tcp.parse_segment(fin_segment1)
      fin_seq = parsed1.seq

      assert :fin in parsed1.flags
      assert parsed1.payload == <<>>

      assert_receive {:dummy_link_packet, _link, fin_packet2}, 1500
      <<_ip_header::binary-size(40), fin_segment2::binary>> = fin_packet2
      parsed2 = Tcp.parse_segment(fin_segment2)

      assert :fin in parsed2.flags
      assert :ack in parsed2.flags
      assert parsed2.seq == parsed1.seq
      assert parsed2.payload == <<>>

      {:fin_wait_1, state} = :sys.get_state(socket)
      assert [{^fin_seq, _seq_end, :fin, 1}] = state.unacked_segments
    end

    test "ACK of data after close keeps FIN pending in FIN_WAIT_1", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      assert Tricep.send(socket, "data") == :ok
      assert_receive {:dummy_link_packet, _link, data_packet}, 1000

      <<_ip_header::binary-size(40), data_segment::binary>> = data_packet
      data = Tcp.parse_segment(data_segment)

      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, fin_packet}, 1000

      <<_ip_header::binary-size(40), fin_segment::binary>> = fin_packet
      fin = Tcp.parse_segment(fin_segment)

      {:fin_wait_1, close_state} = :sys.get_state(socket)
      assert length(close_state.unacked_segments) == 2

      data_ack = wrap_seq(data.seq + byte_size(data.payload))

      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          data_ack,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      {:fin_wait_1, acked_state} = :sys.get_state(socket)
      assert acked_state.snd_una == data_ack
      assert [{fin_seq, fin_end, :fin, _count}] = acked_state.unacked_segments
      assert fin_seq == fin.seq
      assert fin_end == wrap_seq(fin.seq + 1)
      assert acked_state.rto_timer_active == true

      fin_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          acked_state.snd_nxt,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, fin_ack)

      {:fin_wait_2, fin_acked_state} = :sys.get_state(socket)
      assert fin_acked_state.unacked_segments == []
      assert fin_acked_state.rto_timer_active == false
    end

    test "FIN retry exhaustion closes FIN_WAIT_1", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      :sys.replace_state(socket, fn
        {:fin_wait_1, state} ->
          unacked_segments =
            Enum.map(state.unacked_segments, fn {seq_start, seq_end, payload, _count} ->
              {seq_start, seq_end, payload, 5}
            end)

          {:fin_wait_1, %{state | unacked_segments: unacked_segments}}
      end)

      wait_for_state_name(socket, :closed, 1500)
    end
  end

  describe "FIN_WAIT_2 state" do
    test "times out and closes if peer FIN never arrives", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket =
        establish_connection(
          link,
          local_addr,
          remote_addr,
          open_opts: %{fin_wait_2_timeout_ms: 50}
        )

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      {:fin_wait_2, _} = :sys.get_state(socket)
      wait_for_state_name(socket, :closed, 1000)
    end

    test "RST in FIN_WAIT_2 closes connection", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Close and get to FIN_WAIT_2
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      # Send ACK of our FIN
      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      {:fin_wait_2, _} = :sys.get_state(socket)

      # Send RST
      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      {:closed, nil} = :sys.get_state(socket)
    end

    test "data in FIN_WAIT_2 is buffered (half-close)", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Close and get to FIN_WAIT_2
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      # Send ACK of our FIN
      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      {:fin_wait_2, _} = :sys.get_state(socket)

      # Send data (half-close allows peer to still send)
      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:ack, :psh],
          32768,
          payload: "Half-close data"
        )

      DummyLink.inject_packet(link, data_segment)

      # Data should be buffered
      {:fin_wait_2, fin_wait_2_state} = :sys.get_state(socket)
      assert fin_wait_2_state.recv_buffer == "Half-close data"

      # Should have sent ACK
      assert_receive {:dummy_link_packet, _link, _data_ack}, 1000
    end

    test "ignores malformed segment in FIN_WAIT_2", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Close and get to FIN_WAIT_2
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      {:fin_wait_2, _} = :sys.get_state(socket)

      # Inject malformed segment
      DummyLink.inject_packet(link, <<1, 2, 3>>)

      # Should still be in FIN_WAIT_2
      {:fin_wait_2, _} = :sys.get_state(socket)
    end

    test "ACKs unexpected data in FIN_WAIT_2 without buffering", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Close and get to FIN_WAIT_2
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      {:fin_wait_2, _} = :sys.get_state(socket)

      # Send segment with wrong seq (out of order)
      wrong_seq =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1000,
          state.snd_nxt + 1,
          [:ack, :psh],
          32768,
          payload: "Wrong seq"
        )

      DummyLink.inject_packet(link, wrong_seq)

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert :ack in ack.flags
      assert ack.ack == state.irs + 1

      # Should still be in FIN_WAIT_2 with empty buffer
      {:fin_wait_2, fin_wait_2_state} = :sys.get_state(socket)
      assert fin_wait_2_state.recv_buffer == <<>>
    end
  end

  describe "TIME_WAIT state" do
    test "TIME_WAIT expires and closes connection", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Close and get to TIME_WAIT via FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      # ACK our FIN
      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      {:fin_wait_2, _} = :sys.get_state(socket)

      # Send FIN from peer
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:time_wait, _} = :sys.get_state(socket)

      # Drain ACK for peer's FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      wait_for_state_name(socket, :closed, 2_500)
    end

    test "FIN retransmit in TIME_WAIT is re-ACKed", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Get to TIME_WAIT
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      # ACK our FIN
      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      # Send FIN from peer
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:time_wait, _} = :sys.get_state(socket)

      # Drain first ACK
      assert_receive {:dummy_link_packet, _link, _first_ack}, 1000

      # Send FIN again (simulating retransmit because peer didn't get our ACK)
      DummyLink.inject_packet(link, fin_segment)

      # Should re-ACK
      assert_receive {:dummy_link_packet, _link, re_ack_packet}, 1000
      <<_::binary-size(40), re_ack_seg::binary>> = re_ack_packet
      assert :ack in Tcp.parse_segment(re_ack_seg).flags

      # Should still be in TIME_WAIT
      {:time_wait, _} = :sys.get_state(socket)
    end

    test "non-FIN segment in TIME_WAIT is ignored", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Get to TIME_WAIT
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:time_wait, _} = :sys.get_state(socket)

      # Drain first ACK
      assert_receive {:dummy_link_packet, _link, _first_ack}, 1000

      # Send non-FIN segment (just ACK)
      just_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 2,
          state.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, just_ack)

      # Should not send any response (no new packet)
      refute_receive {:dummy_link_packet, _link, _}, 100

      # Should still be in TIME_WAIT
      {:time_wait, _} = :sys.get_state(socket)
    end
  end

  describe "CLOSING state" do
    test "RST in CLOSING closes connection", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Close to enter FIN_WAIT_1
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      {:fin_wait_1, _} = :sys.get_state(socket)

      # Send FIN without ACK of our FIN (simultaneous close)
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:closing, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _their_fin_ack}, 1000

      # Send RST
      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 2,
          state.snd_nxt + 1,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      {:closed, nil} = :sys.get_state(socket)
    end

    test "ACK of our FIN in CLOSING goes to TIME_WAIT", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Close to enter FIN_WAIT_1
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      {:fin_wait_1, _} = :sys.get_state(socket)

      # Send FIN without ACK of our FIN (simultaneous close)
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:closing, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _their_fin_ack}, 1000

      # Now send ACK of our FIN
      our_fin_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 2,
          state.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, our_fin_ack)

      {:time_wait, _} = :sys.get_state(socket)
    end

    test "ignores malformed segment in CLOSING", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Close to enter FIN_WAIT_1
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      # Send FIN without ACK of our FIN (simultaneous close)
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:closing, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _their_fin_ack}, 1000

      # Inject malformed segment
      DummyLink.inject_packet(link, <<1, 2, 3>>)

      # Should still be in CLOSING
      {:closing, _} = :sys.get_state(socket)
    end

    test "ignores unexpected segment in CLOSING", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Close to enter FIN_WAIT_1
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      # Send FIN without ACK of our FIN (simultaneous close)
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:closing, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _their_fin_ack}, 1000

      # Send ACK with wrong ack number
      wrong_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 2,
          state.snd_nxt,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, wrong_ack)

      # Should still be in CLOSING (wrong ACK ignored)
      {:closing, _} = :sys.get_state(socket)
    end
  end

  describe "CLOSE_WAIT state" do
    test "can send data in CLOSE_WAIT", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Send FIN from peer (passive close)
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:close_wait, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Should still be able to send data
      assert Tricep.send(socket, "Data after peer FIN") == :ok

      # Should receive data segment
      assert_receive {:dummy_link_packet, _link, data_packet}, 1000
      <<_::binary-size(40), data_seg::binary>> = data_packet
      parsed = Tcp.parse_segment(data_seg)
      assert parsed.payload == "Data after peer FIN"
    end

    test "can send large data segmented in CLOSE_WAIT", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, mss: 10)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Send FIN from peer
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:close_wait, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Send large data that will be segmented
      assert Tricep.send(socket, "Hello, World!") == :ok

      # Should receive two segments
      assert_receive {:dummy_link_packet, _link, packet1}, 1000
      assert_receive {:dummy_link_packet, _link, packet2}, 1000

      <<_::binary-size(40), seg1::binary>> = packet1
      <<_::binary-size(40), seg2::binary>> = packet2

      parsed1 = Tcp.parse_segment(seg1)
      parsed2 = Tcp.parse_segment(seg2)

      assert parsed1.payload == "Hello, Wor"
      assert parsed2.payload == "ld!"
    end

    test "close in CLOSE_WAIT sends FIN and goes to LAST_ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Send FIN from peer
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:close_wait, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Close our side
      assert Tricep.close(socket) == :ok

      # Should receive our FIN
      assert_receive {:dummy_link_packet, _link, our_fin_packet}, 1000
      <<_::binary-size(40), our_fin_seg::binary>> = our_fin_packet
      parsed = Tcp.parse_segment(our_fin_seg)
      assert :fin in parsed.flags

      # Should be in LAST_ACK
      {:last_ack, _} = :sys.get_state(socket)
    end

    test "RST in CLOSE_WAIT closes connection", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Send FIN from peer
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:close_wait, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Send RST
      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 2,
          state.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      {:closed, nil} = :sys.get_state(socket)
    end

    test "ACK in CLOSE_WAIT updates snd_una", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Send FIN from peer
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:close_wait, close_wait_state} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Send data
      assert Tricep.send(socket, "Test") == :ok
      assert_receive {:dummy_link_packet, _link, _data_packet}, 1000

      # Send ACK for our data
      data_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 2,
          close_wait_state.snd_nxt + 4,
          [:ack],
          65535
        )

      DummyLink.inject_packet(link, data_ack)

      # snd_una should be updated
      {:close_wait, updated_state} = :sys.get_state(socket)
      assert updated_state.snd_una == close_wait_state.snd_nxt + 4
      assert updated_state.snd_wnd == 65535
    end

    test "off-window ACK in CLOSE_WAIT does not update send state", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:close_wait, _close_wait_state} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      assert Tricep.send(socket, "Test") == :ok
      assert_receive {:dummy_link_packet, _link, _data_packet}, 1000

      {:close_wait, state_before_ack} = :sys.get_state(socket)

      off_window_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state_before_ack.rcv_nxt - 1),
          state_before_ack.snd_nxt,
          [:ack],
          65_535
        )

      DummyLink.inject_packet(link, off_window_ack)

      assert_receive {:dummy_link_packet, _link, challenge_packet}, 1000
      <<_ip_header::binary-size(40), challenge_segment::binary>> = challenge_packet
      challenge = Tcp.parse_segment(challenge_segment)

      assert :ack in challenge.flags
      assert challenge.seq == state_before_ack.snd_nxt
      assert challenge.ack == state_before_ack.rcv_nxt

      {:close_wait, state_after_ack} = :sys.get_state(socket)

      assert state_after_ack.snd_una == state_before_ack.snd_una
      assert state_after_ack.snd_wnd == state_before_ack.snd_wnd
      assert state_after_ack.unacked_segments == state_before_ack.unacked_segments
      assert state_after_ack.rto_timer_active == state_before_ack.rto_timer_active
    end

    test "ignores malformed segment in CLOSE_WAIT", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Send FIN from peer
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:close_wait, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Inject malformed segment
      DummyLink.inject_packet(link, <<1, 2, 3>>)

      # Should still be in CLOSE_WAIT
      {:close_wait, _} = :sys.get_state(socket)
    end
  end

  describe "LAST_ACK state" do
    test "RST in LAST_ACK closes connection", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Send FIN from peer to get to CLOSE_WAIT
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:close_wait, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Close to get to LAST_ACK
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _our_fin}, 1000

      {:last_ack, _} = :sys.get_state(socket)

      # Send RST
      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 2,
          state.snd_nxt + 1,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      {:closed, nil} = :sys.get_state(socket)
    end

    test "ACK of our FIN in LAST_ACK closes connection", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Send FIN from peer to get to CLOSE_WAIT
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:close_wait, _close_wait_state} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Close to get to LAST_ACK
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _our_fin}, 1000

      {:last_ack, last_ack_state} = :sys.get_state(socket)

      # Send ACK of our FIN
      our_fin_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 2,
          last_ack_state.snd_nxt,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, our_fin_ack)

      {:closed, nil} = :sys.get_state(socket)
    end

    test "retransmits lost FIN in LAST_ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:close_wait, _close_wait_state} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      assert Tricep.close(socket) == :ok

      assert_receive {:dummy_link_packet, _link, fin_packet1}, 1000
      <<_ip_header::binary-size(40), fin_segment1::binary>> = fin_packet1
      parsed1 = Tcp.parse_segment(fin_segment1)

      assert :fin in parsed1.flags
      assert parsed1.payload == <<>>

      assert_receive {:dummy_link_packet, _link, fin_packet2}, 1500
      <<_ip_header::binary-size(40), fin_segment2::binary>> = fin_packet2
      parsed2 = Tcp.parse_segment(fin_segment2)

      assert :fin in parsed2.flags
      assert :ack in parsed2.flags
      assert parsed2.seq == parsed1.seq
      assert parsed2.payload == <<>>

      {:last_ack, state} = :sys.get_state(socket)
      assert [{_seq, _seq_end, :fin, 1}] = state.unacked_segments
    end

    test "ignores malformed segment in LAST_ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Send FIN from peer to get to CLOSE_WAIT
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:close_wait, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Close to get to LAST_ACK
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _our_fin}, 1000

      {:last_ack, _} = :sys.get_state(socket)

      # Inject malformed segment
      DummyLink.inject_packet(link, <<1, 2, 3>>)

      # Should still be in LAST_ACK
      {:last_ack, _} = :sys.get_state(socket)
    end

    test "ignores unexpected segment in LAST_ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Send FIN from peer to get to CLOSE_WAIT
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:close_wait, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Close to get to LAST_ACK
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _our_fin}, 1000

      {:last_ack, last_ack_state} = :sys.get_state(socket)

      # Send ACK with wrong ack number
      wrong_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 2,
          last_ack_state.snd_nxt - 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, wrong_ack)

      # Should still be in LAST_ACK (wrong ACK ignored)
      {:last_ack, _} = :sys.get_state(socket)
    end
  end

  describe "SYN retransmission" do
    @tag :slow
    test "retransmits SYN after timeout" do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      # Start connect in a task (it will block waiting for SYN-ACK)
      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      # Wait for the first SYN packet
      assert_receive {:dummy_link_packet, _link, packet1}, 1000

      <<_ip_header::binary-size(40), syn_segment1::binary>> = packet1
      parsed1 = Tcp.parse_segment(syn_segment1)
      assert :syn in parsed1.flags

      # Don't send SYN-ACK, wait for retransmission (RTO = 1000ms)
      # Wait for second SYN
      assert_receive {:dummy_link_packet, _link, packet2}, 1500

      <<_ip_header::binary-size(40), syn_segment2::binary>> = packet2
      parsed2 = Tcp.parse_segment(syn_segment2)
      assert :syn in parsed2.flags
      # Same sequence number as first SYN
      assert parsed2.seq == parsed1.seq

      Task.shutdown(task, :brutal_kill)
    end

    @tag :slow
    @tag timeout: 120_000
    test "connection fails after max SYN retries", %{
      link: _link,
      local_addr: _local_addr,
      remote_addr: _remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      # Drain all SYN packets without responding
      # Timing: initial + retransmits with exponential backoff
      # count=0, RTO=1s -> retransmit -> count=1, RTO=2s
      # count=1, RTO=2s -> retransmit -> count=2, RTO=4s
      # count=2, RTO=4s -> retransmit -> count=3, RTO=8s
      # count=3, RTO=8s -> retransmit -> count=4, RTO=16s
      # count=4, RTO=16s -> retransmit -> count=5, RTO=32s
      # count=5 >= 5, connection fails
      # Total: 1+2+4+8+16+32 = 63s

      # Receive initial SYN
      assert_receive {:dummy_link_packet, _link, _packet0}, 1000

      # Receive retransmission 1 (after ~1s)
      assert_receive {:dummy_link_packet, _link, _packet1}, 1500

      # Receive retransmission 2 (after ~2s more)
      assert_receive {:dummy_link_packet, _link, _packet2}, 2500

      # Receive retransmission 3 (after ~4s more)
      assert_receive {:dummy_link_packet, _link, _packet3}, 4500

      # Receive retransmission 4 (after ~8s more)
      assert_receive {:dummy_link_packet, _link, _packet4}, 8500

      # Receive retransmission 5 (after ~16s more)
      assert_receive {:dummy_link_packet, _link, _packet5}, 16500

      # After 5 retransmissions, the 6th timeout (after ~32s) should fail
      result = Task.await(task, 35_000)
      assert result == {:error, :etimedout}
    end

    @tag :slow
    test "SYN retransmit cancelled on RST", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      # Wait for the first SYN packet
      assert_receive {:dummy_link_packet, _link, packet}, 1000

      <<_ip_header::binary-size(40), syn_segment::binary>> = packet
      <<src_port::16, _::binary>> = syn_segment

      # Send RST response
      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          0,
          0,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      # Connect should fail with connection refused
      assert Task.await(task, 1000) == {:error, :econnrefused}

      # No more SYN retransmissions should occur
      refute_receive {:dummy_link_packet, _link, _}, 1500
    end
  end

  describe "data retransmission" do
    @tag :slow
    test "retransmits data segment after RTO", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Send data
      assert Tricep.send(socket, "Hello") == :ok

      # Should receive data segment
      assert_receive {:dummy_link_packet, _link, data_packet1}, 1000

      <<_ip_header::binary-size(40), data_segment1::binary>> = data_packet1
      parsed1 = Tcp.parse_segment(data_segment1)
      assert parsed1.payload == "Hello"

      # Don't send ACK, wait for retransmission (RTO = 1000ms)
      assert_receive {:dummy_link_packet, _link, data_packet2}, 1500

      <<_ip_header::binary-size(40), data_segment2::binary>> = data_packet2
      parsed2 = Tcp.parse_segment(data_segment2)
      assert parsed2.payload == "Hello"
      assert parsed2.seq == parsed1.seq
    end

    @tag :slow
    test "ACK prevents retransmission", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get socket state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Send data
      assert Tricep.send(socket, "Hello") == :ok

      # Should receive data segment
      assert_receive {:dummy_link_packet, _link, data_packet}, 1000

      <<_ip_header::binary-size(40), data_segment::binary>> = data_packet
      parsed = Tcp.parse_segment(data_segment)

      # Send ACK for the data
      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          parsed.seq + byte_size(parsed.payload),
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      # Wait past the RTO - should NOT receive retransmission
      refute_receive {:dummy_link_packet, _link, _}, 1500
    end

    test "Packet Too Big resegments unacked data before retransmission", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, mss: 1460)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      :sys.replace_state(socket, fn
        {:established, state} -> {:established, %{state | rto_ms: 100}}
      end)

      data = :binary.copy("x", 1400)
      assert Tricep.send(socket, data) == :ok

      assert_receive {:dummy_link_packet, _link, data_packet1}, 1000

      <<_ip_header::binary-size(40), data_segment1::binary>> = data_packet1
      parsed1 = Tcp.parse_segment(data_segment1)

      assert parsed1.payload == data

      send(socket, {:icmpv6_error, {:packet_too_big, 1300}})

      wait_for_socket(socket, fn
        {:established, %{snd_mss: 1240, unacked_segments: segments}} ->
          Enum.map(segments, fn {seq_start, seq_end, payload, _count} ->
            {seq_start, seq_end, byte_size(payload)}
          end) == [
            {parsed1.seq, wrap_seq(parsed1.seq + 1240), 1240},
            {wrap_seq(parsed1.seq + 1240), wrap_seq(parsed1.seq + 1400), 160}
          ]

        _state ->
          false
      end)

      assert_receive {:dummy_link_packet, _link, data_packet2}, 1000

      <<_ip_header::binary-size(40), data_segment2::binary>> = data_packet2
      parsed2 = Tcp.parse_segment(data_segment2)

      assert parsed2.seq == parsed1.seq
      assert parsed2.payload == binary_part(data, 0, 1240)
    end

    test "Packet Too Big below IPv6 minimum does not reduce MSS below floor", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, mss: 1460)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      send(socket, {:icmpv6_error, {:packet_too_big, 1200}})

      wait_for_socket(socket, fn
        {:established, %{snd_mss: 1220}} -> true
        _state -> false
      end)
    end

    @tag :slow
    test "exponential backoff doubles RTO", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Send data
      assert Tricep.send(socket, "Hello") == :ok

      # First transmission
      assert_receive {:dummy_link_packet, _link, _packet1}, 1000
      t1 = System.monotonic_time(:millisecond)

      # First retransmission (after ~1000ms)
      assert_receive {:dummy_link_packet, _link, _packet2}, 1500
      t2 = System.monotonic_time(:millisecond)

      # Second retransmission (after ~2000ms more)
      assert_receive {:dummy_link_packet, _link, _packet3}, 2500
      t3 = System.monotonic_time(:millisecond)

      # Check timing (with some tolerance)
      delta1 = t2 - t1
      delta2 = t3 - t2

      # First retransmit after ~1000ms
      assert delta1 >= 900 and delta1 <= 1500,
             "First retransmit took #{delta1}ms, expected ~1000ms"

      # Second retransmit after ~2000ms (doubled)
      assert delta2 >= 1800 and delta2 <= 2500,
             "Second retransmit took #{delta2}ms, expected ~2000ms"

      # delta2 should be roughly 2x delta1
      assert delta2 > delta1 * 1.5, "Expected exponential backoff"
    end

    @tag :slow
    @tag timeout: 120_000
    test "connection closes after max data retries", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Send data
      assert Tricep.send(socket, "Hello") == :ok

      # Drain all retransmissions without ACKing
      # Initial + 5 retransmissions with exponential backoff: 1+2+4+8+16+32 = 63s
      assert_receive {:dummy_link_packet, _link, _p0}, 1000
      assert_receive {:dummy_link_packet, _link, _p1}, 1500
      assert_receive {:dummy_link_packet, _link, _p2}, 2500
      assert_receive {:dummy_link_packet, _link, _p3}, 4500
      assert_receive {:dummy_link_packet, _link, _p4}, 8500
      assert_receive {:dummy_link_packet, _link, _p5}, 16500

      # Wait for connection to fail after the final retry timeout.
      wait_for_state_name(socket, :closed, 35_000)
    end

    test "data retransmission failure notifies blocking send waiters", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 1)

      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.send(socket, "a") == :ok
      assert_receive {:dummy_link_packet, _link, _data_packet}, 1000

      send_task = Task.async(fn -> Tricep.send(socket, "blocked", :infinity) end)
      wait_for_send_waiters(socket)

      :sys.replace_state(socket, fn
        {:established, state} ->
          unacked_segments =
            Enum.map(state.unacked_segments, fn {seq_start, seq_end, payload, _count} ->
              {seq_start, seq_end, payload, 5}
            end)

          {:established, %{state | unacked_segments: unacked_segments}}
      end)

      assert Task.await(send_task, 1500) == {:error, :etimedout}
      {:closed, nil} = :sys.get_state(socket)
    end

    test "duplicate ACK leaves retransmission state intact", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.send(socket, "Hello") == :ok
      assert_receive {:dummy_link_packet, _link, _data_packet}, 1000

      {:established, state_before_ack} = :sys.get_state(socket)
      {{_, src_port}, _} = state_before_ack.pair

      assert length(state_before_ack.unacked_segments) == 1
      assert state_before_ack.rto_timer_active == true

      inject_ack(
        link,
        local_addr,
        remote_addr,
        src_port,
        state_before_ack.rcv_nxt,
        state_before_ack.snd_una,
        12_345
      )

      {:established, state_after_ack} = :sys.get_state(socket)

      assert state_after_ack.snd_una == state_before_ack.snd_una
      assert state_after_ack.snd_nxt == state_before_ack.snd_nxt
      assert state_after_ack.unacked_segments == state_before_ack.unacked_segments
      assert state_after_ack.rto_timer_active == true
      assert state_after_ack.snd_wnd == 12_345
      refute_receive {:dummy_link_packet, _link, _packet}, 100
    end

    test "valid partial ACK advances snd_una and keeps later unacked segments", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, mss: 5)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.send(socket, "helloworld") == :ok

      assert_receive {:dummy_link_packet, _link, packet1}, 1000
      assert_receive {:dummy_link_packet, _link, packet2}, 1000

      <<_ip_header::binary-size(40), segment1::binary>> = packet1
      <<_ip_header::binary-size(40), segment2::binary>> = packet2
      parsed1 = Tcp.parse_segment(segment1)
      parsed2 = Tcp.parse_segment(segment2)

      {:established, state_before_ack} = :sys.get_state(socket)
      {{_, src_port}, _} = state_before_ack.pair

      assert length(state_before_ack.unacked_segments) == 2

      partial_ack = wrap_seq(parsed1.seq + byte_size(parsed1.payload))

      inject_ack(
        link,
        local_addr,
        remote_addr,
        src_port,
        state_before_ack.rcv_nxt,
        partial_ack,
        40_000
      )

      {:established, state_after_ack} = :sys.get_state(socket)

      assert state_after_ack.snd_una == partial_ack
      assert state_after_ack.snd_nxt == state_before_ack.snd_nxt
      assert state_after_ack.rto_timer_active == true

      assert [{seq_start, seq_end, payload, _count}] = state_after_ack.unacked_segments
      assert seq_start == parsed2.seq
      assert seq_end == wrap_seq(parsed2.seq + byte_size(parsed2.payload))
      assert payload == parsed2.payload
    end

    test "valid full ACK clears all retransmission state", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.send(socket, "Hello") == :ok
      assert_receive {:dummy_link_packet, _link, data_packet}, 1000

      <<_ip_header::binary-size(40), data_segment::binary>> = data_packet
      parsed = Tcp.parse_segment(data_segment)

      {:established, state_before_ack} = :sys.get_state(socket)
      {{_, src_port}, _} = state_before_ack.pair

      assert length(state_before_ack.unacked_segments) == 1

      full_ack = wrap_seq(parsed.seq + byte_size(parsed.payload))

      inject_ack(
        link,
        local_addr,
        remote_addr,
        src_port,
        state_before_ack.rcv_nxt,
        full_ack
      )

      {:established, state_after_ack} = :sys.get_state(socket)

      assert state_after_ack.snd_una == full_ack
      assert state_after_ack.snd_una == state_before_ack.snd_nxt
      assert state_after_ack.unacked_segments == []
      assert state_after_ack.rto_timer_active == false
    end

    test "ACK beyond snd_nxt is rejected without dropping unacked segments", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.send(socket, "Hello") == :ok
      assert_receive {:dummy_link_packet, _link, _data_packet}, 1000

      {:established, state_before_ack} = :sys.get_state(socket)
      {{_, src_port}, _} = state_before_ack.pair

      assert length(state_before_ack.unacked_segments) == 1
      invalid_ack = wrap_seq(state_before_ack.snd_nxt + 1)

      inject_ack(
        link,
        local_addr,
        remote_addr,
        src_port,
        state_before_ack.rcv_nxt,
        invalid_ack,
        1
      )

      assert_receive {:dummy_link_packet, _link, corrective_packet}, 1000
      <<_ip_header::binary-size(40), corrective_segment::binary>> = corrective_packet
      corrective = Tcp.parse_segment(corrective_segment)

      assert :ack in corrective.flags
      assert corrective.seq == state_before_ack.snd_nxt
      assert corrective.ack == state_before_ack.rcv_nxt

      {:established, state_after_ack} = :sys.get_state(socket)

      assert state_after_ack.snd_una == state_before_ack.snd_una
      assert state_after_ack.snd_nxt == state_before_ack.snd_nxt
      assert state_after_ack.snd_wnd == state_before_ack.snd_wnd
      assert state_after_ack.unacked_segments == state_before_ack.unacked_segments
      assert state_after_ack.rto_timer_active == true
    end

    test "unacked_segments cleared after ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get socket state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Send data
      assert Tricep.send(socket, "Hello") == :ok

      # Should receive data segment
      assert_receive {:dummy_link_packet, _link, data_packet}, 1000

      <<_ip_header::binary-size(40), data_segment::binary>> = data_packet
      parsed = Tcp.parse_segment(data_segment)

      # Check that unacked_segments is not empty
      {:established, state_before_ack} = :sys.get_state(socket)
      assert length(state_before_ack.unacked_segments) == 1

      # Send ACK for the data
      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          parsed.seq + byte_size(parsed.payload),
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      # Check that unacked_segments is now empty
      {:established, state_after_ack} = :sys.get_state(socket)
      assert state_after_ack.unacked_segments == []
      assert state_after_ack.rto_timer_active == false
    end

    test "retransmission in CLOSE_WAIT state", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get socket state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Send FIN from peer to enter CLOSE_WAIT
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:close_wait, _} = :sys.get_state(socket)

      # Drain ACK for FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Send data in CLOSE_WAIT
      assert Tricep.send(socket, "Data") == :ok

      # Should receive data segment
      assert_receive {:dummy_link_packet, _link, data_packet1}, 1000

      <<_ip_header::binary-size(40), data_segment1::binary>> = data_packet1
      parsed1 = Tcp.parse_segment(data_segment1)
      assert parsed1.payload == "Data"

      # Don't ACK, wait for retransmission
      assert_receive {:dummy_link_packet, _link, data_packet2}, 1500

      <<_ip_header::binary-size(40), data_segment2::binary>> = data_packet2
      parsed2 = Tcp.parse_segment(data_segment2)
      assert parsed2.payload == "Data"
      assert parsed2.seq == parsed1.seq
    end
  end

  # Helper to establish a connection and return the socket
  defp establish_connection(link, local_addr, remote_addr, opts \\ []) do
    open_opts = Keyword.get(opts, :open_opts, %{})
    {:ok, socket} = Tricep.open(:inet6, :stream, :tcp, open_opts)

    task =
      Task.async(fn ->
        Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
      end)

    # Wait for SYN
    assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

    <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
    syn_parsed = Tcp.parse_segment(syn_segment)
    <<src_port::16, _::binary>> = syn_segment

    # Build SYN-ACK with optional MSS/window
    server_seq = 5000
    mss = Keyword.get(opts, :mss)
    window = Keyword.get(opts, :window, 32768)

    segment_opts = if mss, do: [mss: mss], else: []

    syn_ack_segment =
      Tcp.build_segment(
        {{local_addr, @port}, {remote_addr, src_port}},
        server_seq,
        syn_parsed.seq + 1,
        [:syn, :ack],
        window,
        segment_opts
      )

    DummyLink.inject_packet(link, syn_ack_segment)

    assert Task.await(task, 1000) == :ok

    socket
  end

  defp start_pending_blocking_connect do
    {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

    task =
      Task.async(fn ->
        Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
      end)

    assert_receive {:dummy_link_packet, _link, _syn_packet}, 1000
    assert {{:syn_sent, _}, _state} = :sys.get_state(socket)

    {socket, task}
  end

  defp start_pending_nowait_connect do
    {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

    assert {:select, {:select_info, :connect, ref}} =
             Tricep.connect(
               socket,
               %{family: :inet6, addr: @local_addr_str, port: @port},
               :nowait
             )

    assert is_reference(ref)
    assert_receive {:dummy_link_packet, _link, _syn_packet}, 1000
    assert {{:syn_sent, :nowait}, _state} = :sys.get_state(socket)

    socket
  end

  defp assert_pending_connect_operations_return_enotconn(socket) do
    assert Tricep.send(socket, "x", :nowait) == {:error, :enotconn}
    assert Tricep.recv(socket, 0, :nowait) == {:error, :enotconn}
    assert Tricep.close(socket) == {:error, :enotconn}
    assert Tricep.shutdown(socket, :write) == {:error, :enotconn}
    assert Process.alive?(socket)
  end

  # --- Timeout and :nowait tests ---

  describe "connect with :nowait" do
    test "returns select tuple immediately", %{} do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      result =
        Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port}, :nowait)

      assert {:select, {:select_info, :connect, ref}} = result
      assert is_reference(ref)

      # SYN should still be sent
      assert_receive {:dummy_link_packet, _link, packet}, 1000
      <<_ip_header::binary-size(40), tcp_segment::binary>> = packet
      parsed = Tcp.parse_segment(tcp_segment)
      assert :syn in parsed.flags
    end

    test "sends notification on SYN-ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      {:select, {:select_info, :connect, ref}} =
        Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port}, :nowait)

      # Wait for SYN
      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000
      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn_parsed = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      # Inject SYN-ACK
      server_seq = 5000

      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          server_seq,
          syn_parsed.seq + 1,
          [:syn, :ack],
          32768
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      # Should receive select notification
      assert_receive {:"$socket", ^socket, :select, ^ref}, 1000

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000
    end

    test "nowait connect accepts SYN-ACK that acknowledges wrapped active-open ISS", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      {:select, {:select_info, :connect, ref}} =
        Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port}, :nowait)

      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000
      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      <<src_port::16, _::binary>> = syn_segment

      :sys.replace_state(socket, fn
        {{:syn_sent, :nowait}, state} ->
          {{:syn_sent, :nowait}, %{state | iss: 0xFFFFFFFF, snd_una: 0xFFFFFFFF, snd_nxt: 0}}
      end)

      server_seq = 5000

      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          server_seq,
          0,
          [:syn, :ack],
          32768
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      assert_receive {:"$socket", ^socket, :select, ^ref}, 1000
      assert Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port}) == :ok

      assert {:established, %{snd_una: 0, snd_nxt: 0, rcv_nxt: 5001}} = :sys.get_state(socket)

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert :ack in ack.flags
      assert ack.seq == 0
      assert ack.ack == server_seq + 1
    end

    test "subsequent connect returns :ok after notification", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      {:select, {:select_info, :connect, ref}} =
        Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port}, :nowait)

      # Wait for SYN
      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000
      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn_parsed = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      # Inject SYN-ACK
      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn_parsed.seq + 1,
          [:syn, :ack],
          32768
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      # Wait for notification
      assert_receive {:"$socket", ^socket, :select, ^ref}, 1000

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Retrying connect completes the :nowait operation
      assert Tricep.connect(
               socket,
               %{family: :inet6, addr: @local_addr_str, port: @port},
               :nowait
             ) ==
               :ok

      # Further connect attempts should still report that the socket is connected
      assert Tricep.connect(
               socket,
               %{family: :inet6, addr: @local_addr_str, port: @port},
               :nowait
             ) ==
               {:error, :eisconn}
    end

    test "multiple pending selectors are all notified", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      {:select, {:select_info, :connect, ref1}} =
        Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port}, :nowait)

      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000
      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn_parsed = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      {:select, {:select_info, :connect, ref2}} =
        Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port}, :nowait)

      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn_parsed.seq + 1,
          [:syn, :ack],
          32768
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      assert_receive {:"$socket", ^socket, :select, ^ref1}, 1000
      assert_receive {:"$socket", ^socket, :select, ^ref2}, 1000

      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.connect(
               socket,
               %{family: :inet6, addr: @local_addr_str, port: @port},
               :nowait
             ) == :ok

      assert Tricep.connect(
               socket,
               %{family: :inet6, addr: @local_addr_str, port: @port},
               :nowait
             ) == :ok

      assert Tricep.connect(
               socket,
               %{family: :inet6, addr: @local_addr_str, port: @port},
               :nowait
             ) == {:error, :eisconn}
    end
  end

  describe "connect with timeout" do
    test "returns {:error, :einval} for negative timeout" do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      result =
        Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port}, -1)

      assert result == {:error, :einval}
      assert Process.alive?(socket)
      refute_receive {:dummy_link_packet, _link, _packet}, 100
    end

    test "returns {:error, :timeout} when no SYN-ACK received", %{} do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      start_time = System.monotonic_time(:millisecond)

      result =
        Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port}, 200)

      elapsed = System.monotonic_time(:millisecond) - start_time

      assert result == {:error, :timeout}
      # Should have waited approximately 200ms (allow some variance)
      assert elapsed >= 180 and elapsed < 400
    end
  end

  describe "operations during pending connect" do
    test "send, recv, close, and shutdown return errors during blocking connect" do
      {socket, connect_task} = start_pending_blocking_connect()

      assert_pending_connect_operations_return_enotconn(socket)
      assert {{:syn_sent, _}, _state} = :sys.get_state(socket)

      Task.shutdown(connect_task, :brutal_kill)
    end

    test "send, recv, close, and shutdown return errors during :nowait connect" do
      socket = start_pending_nowait_connect()

      assert_pending_connect_operations_return_enotconn(socket)
      assert {{:syn_sent, :nowait}, _state} = :sys.get_state(socket)
    end
  end

  describe "recv with :nowait" do
    test "returns data if buffered", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get source port for building data segment
      src_port = get_socket_src_port(socket)

      # Inject data
      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5001,
          wrap_seq(get_socket_snd_nxt(socket)),
          [:ack],
          32768,
          payload: "buffered data"
        )

      DummyLink.inject_packet(link, data_segment)

      # Drain data ACK
      assert_receive {:dummy_link_packet, _link, _data_ack}, 1000

      # recv with :nowait should return data immediately
      assert Tricep.recv(socket, 0, :nowait) == {:ok, "buffered data"}
    end

    test "returns select tuple if no data", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # recv with :nowait should return select tuple
      result = Tricep.recv(socket, 0, :nowait)
      assert {:select, {:select_info, :recv, ref}} = result
      assert is_reference(ref)
    end

    test "notification sent when data arrives", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Start recv with :nowait
      {:select, {:select_info, :recv, ref}} = Tricep.recv(socket, 0, :nowait)

      # Get source port for building data segment
      src_port = get_socket_src_port(socket)

      # Inject data
      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5001,
          wrap_seq(get_socket_snd_nxt(socket)),
          [:ack],
          32768,
          payload: "arriving data"
        )

      DummyLink.inject_packet(link, data_segment)

      # Should receive notification
      assert_receive {:"$socket", ^socket, :select, ^ref}, 1000

      # Drain data ACK
      assert_receive {:dummy_link_packet, _link, _data_ack}, 1000

      # Now recv should return data
      assert Tricep.recv(socket, 0, :nowait) == {:ok, "arriving data"}
    end

    test "multiple pending selectors are all notified when data arrives", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:select, {:select_info, :recv, ref1}} = Tricep.recv(socket, 0, :nowait)
      {:select, {:select_info, :recv, ref2}} = Tricep.recv(socket, 0, :nowait)

      src_port = get_socket_src_port(socket)

      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5001,
          wrap_seq(get_socket_snd_nxt(socket)),
          [:ack],
          32768,
          payload: "arriving data"
        )

      DummyLink.inject_packet(link, data_segment)

      assert_receive {:"$socket", ^socket, :select, ^ref1}, 1000
      assert_receive {:"$socket", ^socket, :select, ^ref2}, 1000

      assert_receive {:dummy_link_packet, _link, _data_ack}, 1000

      assert Tricep.recv(socket, 0, :nowait) == {:ok, "arriving data"}
    end
  end

  describe "send with :nowait" do
    test "returns :ok if window available", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Send with :nowait should return :ok when window is available
      assert Tricep.send(socket, "test data", :nowait) == :ok

      # Data should be sent
      assert_receive {:dummy_link_packet, _link, data_packet}, 1000
      <<_ip_header::binary-size(40), tcp_segment::binary>> = data_packet
      parsed = Tcp.parse_segment(tcp_segment)
      assert :ack in parsed.flags
      assert parsed.payload == "test data"
    end
  end

  describe "connect with :nowait edge cases" do
    test "RST during :nowait connect notifies and returns econnrefused on retry", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      {:select, {:select_info, :connect, ref}} =
        Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port}, :nowait)

      # Wait for SYN
      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000
      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      <<src_port::16, _::binary>> = syn_segment

      # Send RST
      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          0,
          0,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      assert_receive {:"$socket", ^socket, :select, ^ref}, 1000

      assert Tricep.connect(
               socket,
               %{family: :inet6, addr: @local_addr_str, port: @port},
               :nowait
             ) == {:error, :econnrefused}

      {:closed, nil} = :sys.get_state(socket)
    end

    test "SYN retry exhaustion during :nowait connect notifies and returns etimedout" do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      {:select, {:select_info, :connect, ref}} =
        Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port}, :nowait)

      assert_receive {:dummy_link_packet, _link, _syn_packet}, 1000

      :sys.replace_state(socket, fn
        {{:syn_sent, :nowait}, state} ->
          {{:syn_sent, :nowait}, %{state | syn_retransmit_count: 5}}
      end)

      assert_receive {:"$socket", ^socket, :select, ^ref}, 1500

      assert Tricep.connect(
               socket,
               %{family: :inet6, addr: @local_addr_str, port: @port},
               :nowait
             ) == {:error, :etimedout}

      {:closed, nil} = :sys.get_state(socket)
    end

    test "bad ACK during :nowait connect sends RST", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      {:select, {:select_info, :connect, _ref}} =
        Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port}, :nowait)

      # Wait for SYN
      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000
      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn_parsed = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      # Send SYN-ACK with wrong ACK number
      bad_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn_parsed.seq + 999,
          [:syn, :ack],
          32768
        )

      DummyLink.inject_packet(link, bad_ack_segment)

      # Should receive RST
      assert_receive {:dummy_link_packet, _link, rst_packet}, 1000
      <<_ip_header::binary-size(40), rst_segment::binary>> = rst_packet
      rst_parsed = Tcp.parse_segment(rst_segment)
      assert :rst in rst_parsed.flags
    end
  end

  describe "recv with :nowait edge cases" do
    test "notification sent when FIN arrives with pending recv_select", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Start recv with :nowait
      {:select, {:select_info, :recv, ref}} = Tricep.recv(socket, 0, :nowait)

      # Get source port
      src_port = get_socket_src_port(socket)

      # Send FIN
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5001,
          wrap_seq(get_socket_snd_nxt(socket)),
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      # Should receive notification
      assert_receive {:"$socket", ^socket, :select, ^ref}, 1000

      # Drain FIN ACK
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Now recv should return EOF
      assert Tricep.recv(socket, 0, :nowait) == {:ok, <<>>}
    end
  end

  describe "send blocking with window exhaustion" do
    test "send with :infinity blocks until window opens", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      # Establish connection with small window
      socket = establish_connection(link, local_addr, remote_addr, mss: 100)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get source port
      src_port = get_socket_src_port(socket)
      {:established, state} = :sys.get_state(socket)

      # Fill the send window by sending data without ACKing
      # Window is 32768, send enough to exhaust it
      big_data = :crypto.strong_rand_bytes(32768)
      assert Tricep.send(socket, big_data, :nowait) == :ok

      # Drain all the data segments
      drain_packets(33)

      # Now window should be exhausted - next send should block
      send_task = Task.async(fn -> Tricep.send(socket, "more data", :infinity) end)

      wait_for_send_waiters(socket)

      # Send ACK to open window
      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          wrap_seq(state.snd_nxt + byte_size(big_data)),
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      # Send should complete
      assert Task.await(send_task, 1000) == :ok
    end

    test "multiple blocking sends proceed when one window update has enough space", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 0)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      send_task1 = Task.async(fn -> Tricep.send(socket, "aa", :infinity) end)
      wait_for_send_waiters(socket)

      send_task2 = Task.async(fn -> Tricep.send(socket, "bb", :infinity) end)
      wait_for_send_waiters(socket, 2)

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      window_update =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:ack],
          4
        )

      DummyLink.inject_packet(link, window_update)

      assert Task.await(send_task1, 1000) == :ok
      assert Task.await(send_task2, 1000) == :ok

      assert_receive {:dummy_link_packet, _link, data_packet}, 1000
      <<_ip_header::binary-size(40), data_segment::binary>> = data_packet
      parsed = Tcp.parse_segment(data_segment)

      assert parsed.payload == "aabb"
    end

    test "zero-window persist probes continue until a fresh window update arrives", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 0)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      send_task = Task.async(fn -> Tricep.send(socket, "abc", :infinity) end)
      wait_for_send_waiters(socket)

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      assert state.persist_timer_active
      assert state.persist_timeout_ms == 1_000
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      assert_receive {:dummy_link_packet, _link, probe_packet}, 1500
      <<_ip_header::binary-size(40), probe_segment::binary>> = probe_packet
      probe = Tcp.parse_segment(probe_segment)

      assert probe.payload == "a"
      assert probe.seq == wrap_seq(state.snd_nxt - 1)

      {:established, after_probe} = :sys.get_state(socket)
      assert after_probe.persist_timer_active
      assert after_probe.persist_timeout_ms == 2_000

      window_update =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:ack],
          3
        )

      DummyLink.inject_packet(link, window_update)

      assert Task.await(send_task, 1000) == :ok

      assert_receive {:dummy_link_packet, _link, data_packet}, 1000
      <<_ip_header::binary-size(40), data_segment::binary>> = data_packet
      data = Tcp.parse_segment(data_segment)

      assert data.payload == "abc"
      assert data.seq == state.snd_nxt

      {:established, opened_state} = :sys.get_state(socket)
      refute opened_state.persist_timer_active
    end
  end

  # Helper functions for timeout tests
  defp inject_ack(link, local_addr, remote_addr, src_port, seq, ack, window \\ 32_768) do
    ack_segment =
      Tcp.build_segment(
        {{local_addr, @port}, {remote_addr, src_port}},
        seq,
        ack,
        [:ack],
        window
      )

    DummyLink.inject_packet(link, ack_segment)
  end

  defp get_socket_src_port(socket) do
    {_state_name, state} = :sys.get_state(socket)
    {{_, src_port}, _} = state.pair
    src_port
  end

  defp get_socket_snd_nxt(socket) do
    {_state_name, state} = :sys.get_state(socket)
    state.snd_nxt
  end

  defp shutdown_write_to_fin_wait_2(socket, link, local_addr, remote_addr) do
    # Drain the ACK packet from handshake
    assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

    {:established, state} = :sys.get_state(socket)
    {{_, src_port}, _} = state.pair

    assert Tricep.shutdown(socket, :write) == :ok
    assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

    ack_segment =
      Tcp.build_segment(
        {{local_addr, @port}, {remote_addr, src_port}},
        state.irs + 1,
        state.snd_nxt + 1,
        [:ack],
        32768
      )

    DummyLink.inject_packet(link, ack_segment)

    {:fin_wait_2, _state} = :sys.get_state(socket)
    {state, src_port}
  end

  defp wait_for_recv_waiters(socket, count \\ 1) do
    wait_for_socket(socket, fn
      {_state_name, %{recv_waiters: waiters}} -> length(waiters) >= count
      _ -> false
    end)
  end

  defp wait_for_send_waiters(socket, count \\ 1) do
    wait_for_socket(socket, fn
      {_state_name, %{send_waiters: waiters}} -> length(waiters) >= count
      _ -> false
    end)
  end

  defp wait_for_state_name(socket, expected, timeout) do
    wait_for_socket(
      socket,
      fn
        {^expected, _state} -> true
        _ -> false
      end,
      timeout
    )
  end

  defp wait_for_socket(socket, predicate, timeout \\ 1_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    wait_for_socket(socket, predicate, deadline, nil)
  end

  defp wait_for_socket(socket, predicate, deadline, last_state) do
    state = :sys.get_state(socket)

    cond do
      predicate.(state) ->
        state

      System.monotonic_time(:millisecond) >= deadline ->
        flunk("socket did not reach expected state; last state: #{inspect(last_state || state)}")

      true ->
        Process.sleep(1)
        wait_for_socket(socket, predicate, deadline, state)
    end
  end

  defp send_passive_syn(link, local_addr, remote_addr, client_port, client_seq)
       when is_pid(link) do
    syn =
      Tcp.build_segment(
        {{local_addr, client_port}, {remote_addr, @port}},
        client_seq,
        0,
        [:syn],
        32768,
        mss: 1000
      )

    DummyLink.inject_packet(link, syn)

    assert_receive {:dummy_link_packet, _link, packet}, 1000

    <<6::4, _::4, _::24, _payload_len::16, 6::8, _hop::8, pkt_src::binary-size(16),
      pkt_dst::binary-size(16), tcp_segment::binary>> = packet

    parsed = Tcp.parse_segment(tcp_segment)

    assert pkt_src == remote_addr
    assert pkt_dst == local_addr
    assert :syn in parsed.flags
    assert :ack in parsed.flags
    refute :rst in parsed.flags
    assert parsed.ack == client_seq + 1
    assert parsed.options.mss == 1440

    parsed
  end

  defp send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, server_seq) do
    ack =
      Tcp.build_segment(
        {{local_addr, client_port}, {remote_addr, @port}},
        wrap_seq(client_seq + 1),
        wrap_seq(server_seq + 1),
        [:ack],
        32768
      )

    DummyLink.inject_packet(link, ack)
  end

  defp stop_socket(socket) do
    if Process.alive?(socket) do
      Process.exit(socket, :kill)
    end
  catch
    :exit, :noproc -> :ok
    :exit, {:noproc, _} -> :ok
    :exit, :shutdown -> :ok
    :exit, {:shutdown, _} -> :ok
  end

  defp stop_link(link) do
    if Process.alive?(link) do
      GenServer.stop(link)
    end
  catch
    :exit, :noproc -> :ok
    :exit, {:noproc, _} -> :ok
  end

  defp wrap_seq(n), do: Bitwise.band(n, 0xFFFFFFFF)

  defp corrupt_checksum(segment) do
    <<prefix::binary-size(16), checksum::16, suffix::binary>> = segment
    prefix <> <<Bitwise.bxor(checksum, 0x0001)::16>> <> suffix
  end

  defp drain_packets(0), do: :ok

  defp drain_packets(n) do
    receive do
      {:dummy_link_packet, _link, _packet} -> drain_packets(n - 1)
    after
      100 -> :ok
    end
  end

  describe "shutdown/2" do
    test "shutdown(:write) sends FIN and transitions to fin_wait_1", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Shutdown write should return immediately
      assert Tricep.shutdown(socket, :write) == :ok

      # Should receive FIN packet
      assert_receive {:dummy_link_packet, _link, fin_packet}, 1000

      <<_ip_header::binary-size(40), fin_segment::binary>> = fin_packet
      parsed = Tcp.parse_segment(fin_segment)

      assert :fin in parsed.flags
      assert :ack in parsed.flags

      # Should be in FIN_WAIT_1
      {:fin_wait_1, _} = :sys.get_state(socket)
    end

    test "shutdown(:write) releases blocking send waiters", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 0)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      send_task = Task.async(fn -> Tricep.send(socket, "blocked", :infinity) end)
      wait_for_send_waiters(socket)

      {:established, state} = :sys.get_state(socket)
      assert state.persist_timer_active

      assert Tricep.shutdown(socket, :write) == :ok
      assert Task.await(send_task, 1000) == {:error, :epipe}

      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      {:fin_wait_1, state} = :sys.get_state(socket)
      assert state.send_waiters == []
      refute state.persist_timer_active
    end

    test "shutdown(:write) keeps blocking recv waiters usable in fin_wait_1", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      recv_task = Task.async(fn -> Tricep.recv(socket, 0, 5_000) end)
      wait_for_recv_waiters(socket)

      assert Tricep.shutdown(socket, :write) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      {:fin_wait_1, fin_wait_state} = :sys.get_state(socket)
      assert length(fin_wait_state.recv_waiters) == 1

      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "still receiving"
        )

      DummyLink.inject_packet(link, data_segment)

      assert Task.await(recv_task, 1000) == {:ok, "still receiving"}
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:fin_wait_1, fin_wait_state} = :sys.get_state(socket)
      assert fin_wait_state.recv_waiters == []
      assert fin_wait_state.recv_buffer == <<>>
    end

    test "recv after shutdown(:write) returns data buffered in fin_wait_2", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      {state, src_port} = shutdown_write_to_fin_wait_2(socket, link, local_addr, remote_addr)

      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:ack, :psh],
          32768,
          payload: "half-close data"
        )

      DummyLink.inject_packet(link, data_segment)

      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000
      assert Tricep.recv(socket, 0, 1000) == {:ok, "half-close data"}

      {:fin_wait_2, fin_wait_state} = :sys.get_state(socket)
      assert fin_wait_state.recv_buffer == <<>>
    end

    test "nowait recv after shutdown(:write) is notified by data in fin_wait_2", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      {state, src_port} = shutdown_write_to_fin_wait_2(socket, link, local_addr, remote_addr)

      assert {:select, {:select_info, :recv, ref}} = Tricep.recv(socket, 0, :nowait)

      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:ack, :psh],
          32768,
          payload: "ready"
        )

      DummyLink.inject_packet(link, data_segment)

      assert_receive {:"$socket", ^socket, :select, ^ref}, 1000
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000
      assert Tricep.recv(socket, 0, :nowait) == {:ok, "ready"}
    end

    test "recv after shutdown(:write) times out in fin_wait_2", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      shutdown_write_to_fin_wait_2(socket, link, local_addr, remote_addr)

      assert Tricep.recv(socket, 0, 50) == {:error, :timeout}

      {:fin_wait_2, fin_wait_state} = :sys.get_state(socket)
      assert fin_wait_state.recv_waiters == []
    end

    test "blocking recv after shutdown(:write) returns EOF when peer FIN arrives", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      {state, src_port} = shutdown_write_to_fin_wait_2(socket, link, local_addr, remote_addr)

      recv_task = Task.async(fn -> Tricep.recv(socket, 0, 5_000) end)
      wait_for_recv_waiters(socket)

      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      assert Task.await(recv_task, 1000) == {:ok, <<>>}
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:time_wait, _state} = :sys.get_state(socket)
      assert Tricep.recv(socket, 0, 100) == {:ok, <<>>}
    end

    test "shutdown(:write) drains queued send buffer before FIN", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, mss: 10, window: 1)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.send(socket, "xyz") == :ok

      assert_receive {:dummy_link_packet, _link, packet1}, 1000
      <<_ip_header::binary-size(40), segment1::binary>> = packet1
      parsed1 = Tcp.parse_segment(segment1)
      assert parsed1.payload == "x"

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      assert Tricep.shutdown(socket, :write) == :ok
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          wrap_seq(parsed1.seq + byte_size(parsed1.payload)),
          [:ack],
          2
        )

      DummyLink.inject_packet(link, ack_segment)

      assert_receive {:dummy_link_packet, _link, packet2}, 1000
      <<_ip_header::binary-size(40), segment2::binary>> = packet2
      parsed2 = Tcp.parse_segment(segment2)
      assert parsed2.payload == "yz"

      assert_receive {:dummy_link_packet, _link, fin_packet}, 1000
      <<_ip_header::binary-size(40), fin_segment::binary>> = fin_packet
      fin = Tcp.parse_segment(fin_segment)

      assert :fin in fin.flags
      assert fin.seq == wrap_seq(parsed2.seq + byte_size(parsed2.payload))
      assert fin.payload == <<>>

      {:fin_wait_1, _state} = :sys.get_state(socket)
    end

    test "shutdown(:read) marks read as shutdown and stays in established", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Shutdown read should return immediately
      assert Tricep.shutdown(socket, :read) == :ok

      # Should still be in established
      {:established, state} = :sys.get_state(socket)
      assert state.read_shutdown == true

      # No FIN should be sent
      refute_receive {:dummy_link_packet, _link, _fin_packet}, 100
    end

    test "shutdown(:read_write) sends FIN and transitions to fin_wait_1", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Shutdown read_write should return immediately
      assert Tricep.shutdown(socket, :read_write) == :ok

      # Should receive FIN packet
      assert_receive {:dummy_link_packet, _link, fin_packet}, 1000

      <<_ip_header::binary-size(40), fin_segment::binary>> = fin_packet
      parsed = Tcp.parse_segment(fin_segment)

      assert :fin in parsed.flags

      # Should be in FIN_WAIT_1 with read_shutdown set
      {:fin_wait_1, state} = :sys.get_state(socket)
      assert state.read_shutdown == true
    end

    test "recv after shutdown(:read) returns {:error, :closed}", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Shutdown read
      assert Tricep.shutdown(socket, :read) == :ok

      # Recv should return closed
      assert Tricep.recv(socket, 0, 100) == {:error, :closed}
    end

    test "recv after shutdown(:read) returns buffered data first", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Inject data packet
      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.iss + 1,
          [:ack, :psh],
          32768,
          payload: "buffered data"
        )

      DummyLink.inject_packet(link, data_segment)

      # Drain the ACK for the data
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Now shutdown read
      assert Tricep.shutdown(socket, :read) == :ok

      # First recv should return the buffered data
      assert Tricep.recv(socket, 0, 100) == {:ok, "buffered data"}

      # Second recv should return closed
      assert Tricep.recv(socket, 0, 100) == {:error, :closed}
    end

    test "send after shutdown(:write) returns {:error, :epipe}", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Shutdown write
      assert Tricep.shutdown(socket, :write) == :ok

      # Drain the FIN packet
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      # Send should return epipe (socket is in fin_wait_1)
      assert Tricep.send(socket, "data") == {:error, :epipe}
    end

    test "shutdown(:write) in close_wait sends FIN and transitions to last_ack", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Inject FIN from peer
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.iss + 1,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      # Should be in close_wait
      {:close_wait, _} = :sys.get_state(socket)

      # Drain the ACK for the FIN
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Shutdown write
      assert Tricep.shutdown(socket, :write) == :ok

      # Should receive our FIN
      assert_receive {:dummy_link_packet, _link, fin_packet}, 1000

      <<_ip_header::binary-size(40), fin_seg::binary>> = fin_packet
      parsed = Tcp.parse_segment(fin_seg)
      assert :fin in parsed.flags

      # Should be in last_ack
      {:last_ack, _} = :sys.get_state(socket)
    end

    test "shutdown on closed socket returns {:error, :enotconn}", %{} do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.shutdown(socket, :write) == {:error, :enotconn}
      assert Tricep.shutdown(socket, :read) == {:error, :enotconn}
      assert Tricep.shutdown(socket, :read_write) == {:error, :enotconn}
    end
  end
end
