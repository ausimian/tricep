defmodule Tricep.SocketTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Tricep.DummyLink
  alias Tricep.Tcp
  alias Tricep.Tcp.Closing
  alias Tricep.Tcp.ConnectionSupervisor
  alias Tricep.Tcp.Listener
  alias Tricep.Tcp.Listener.{Accepted, Child, Waiter}
  alias Tricep.Tcp.ReceiveReassembly

  defmodule RouteSink do
    use GenServer

    def start_link(owner), do: GenServer.start_link(__MODULE__, owner)

    def register_route(pid, srcaddr, dstaddr, prefix_len, mtu) do
      GenServer.call(pid, {:register_route, srcaddr, dstaddr, prefix_len, mtu})
    end

    @impl true
    def init(owner), do: {:ok, owner}

    @impl true
    def handle_call({:register_route, srcaddr, dstaddr, prefix_len, mtu}, _from, owner) do
      {:reply, Tricep.Application.register_route(srcaddr, dstaddr, prefix_len, mtu), owner}
    end

    @impl true
    def handle_call({:send, packet}, _from, owner) do
      send(owner, {:route_sink_packet, self(), packet})
      {:reply, :ok, owner}
    end
  end

  # Test addresses
  # local_addr: the address Socket connects TO (like ifaddr in TunLink)
  # remote_addr: the address Socket uses as source (like dstaddr in TunLink)
  @local_addr_str "fd00::1"
  @remote_addr_str "fd00::2"
  @port 8080

  setup context do
    # Get binary addresses
    {:ok, local_addr} = Tricep.Address.from(@local_addr_str)
    {:ok, remote_addr} = Tricep.Address.from(@remote_addr_str)

    # Start DummyLink - registers so Socket can find it when connecting to local_addr
    {:ok, link} =
      DummyLink.start_link(
        local_addr: local_addr,
        remote_addr: remote_addr,
        mtu: Map.get(context, :mtu, 1500),
        owner: self()
      )

    on_exit(fn -> stop_link(link) end)

    %{link: link, local_addr: local_addr, remote_addr: remote_addr}
  end

  describe "callback module transitions" do
    test "supports status and code changes through each active callback family", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {opening_socket, opening_task} = start_pending_blocking_connect()

      assert_callback_upgrade(opening_socket)

      Task.shutdown(opening_task, :brutal_kill)
      Process.unlink(opening_socket)
      stop_socket(opening_socket)

      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)

      assert_callback_upgrade(socket)

      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, ^link, _fin_packet}, 1_000
      assert {:fin_wait_1, _state} = :sys.get_state(socket)

      assert_callback_upgrade(socket)
    end
  end

  describe "connect/2" do
    test "rejects links and routes below the IPv6 minimum MTU", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      assert Tricep.Application.register_link(remote_addr, {local_addr, 1279}) ==
               {:error, :invalid_mtu}

      assert Tricep.Application.register_route(remote_addr, local_addr, 64, 1279) ==
               {:error, :invalid_mtu}

      {:ok, minimum_mtu_addr} = Tricep.Address.from("fd00::ffff")

      assert Tricep.Application.register_link(remote_addr, {minimum_mtu_addr, 1280}) == :ok
      assert {_link, {^remote_addr, 1280}} = Tricep.Application.lookup_link(minimum_mtu_addr)
      assert Tricep.Application.deregister_link(minimum_mtu_addr) == :ok
      assert Tricep.Application.lookup_link(minimum_mtu_addr) == nil
    end

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

      route_sink = start_supervised!({RouteSink, self()})

      :ok = RouteSink.register_route(route_sink, remote_addr, local_addr, 64, 1500)

      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: "fd00::abcd", port: @port})
        end)

      assert_receive {:route_sink_packet, ^route_sink, packet}, 1000

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
          {{:syn_sent, from},
           %{state | tcb: %{state.tcb | iss: 0xFFFFFFFF, snd_una: 0xFFFFFFFF, snd_nxt: 0}}}
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

      assert {:established, %{tcb: %{snd_una: 0, snd_nxt: 0, rcv_nxt: 5001}}} =
               :sys.get_state(socket)

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
      syn = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      # Build a RST response
      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          0,
          syn.seq + 1,
          [:rst, :ack],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      # Connect should fail with connection refused
      assert Task.await(task, 1000) == {:error, :econnrefused}
    end

    test "ignores RST whose ACK does not acknowledge the SYN", %{
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
      syn = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      bare_rst =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          0,
          0,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, bare_rst)
      assert {{:syn_sent, _}, _state} = :sys.get_state(socket)

      invalid_rst =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          0,
          syn.seq,
          [:rst, :ack],
          0
        )

      DummyLink.inject_packet(link, invalid_rst)

      assert {{:syn_sent, _}, _state} = :sys.get_state(socket)
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      valid_rst =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          0,
          wrap_seq(syn.seq + 1),
          [:rst, :ack],
          0
        )

      DummyLink.inject_packet(link, valid_rst)
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

      # An ACK at the expected number is not a SYN-ACK and is ignored rather
      # than reset. This characterizes the SYN_SENT distinction between a
      # malformed handshake response and a bare ACK.
      ack_only =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          1001,
          syn_parsed.seq + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_only)
      refute_receive {:dummy_link_packet, _link, _packet}, 50

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
      assert state.tcb.snd_mss == 1000

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

    test "a dead infinite acceptor leaves its next child available and reusable", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(listener, %{family: :inet6, addr: @remote_addr_str, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      acceptor = spawn(fn -> Tricep.accept(listener, :infinity) end)
      acceptor_ref = Process.monitor(acceptor)

      wait_for_socket(listener, fn
        {:listen, %{accept_waiters: [_]}} -> true
        _state -> false
      end)

      Process.exit(acceptor, :kill)
      assert_receive {:DOWN, ^acceptor_ref, :process, ^acceptor, :killed}, 1_000

      wait_for_socket(listener, fn
        {:listen, %{accept_waiters: []}} -> true
        _state -> false
      end)

      client_port = 40_040
      client_seq = 4_000
      syn_ack = send_passive_syn(link, local_addr, remote_addr, client_port, client_seq)
      send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, syn_ack.seq)

      {:listen, %{connection_supervisor: connection_supervisor}} =
        wait_for_socket(listener, fn
          {:listen, %{accept_queue: [_], pending_count: 0}} -> true
          _state -> false
        end)

      [child] = Map.keys(:sys.get_state(connection_supervisor).children)
      assert {:select, {:select_info, :accept, ref}} = Tricep.accept(listener, :nowait)
      assert_receive {:"$socket", ^listener, :select, ^ref}, 1_000
      assert {:ok, ^child} = Tricep.accept(listener, :nowait)

      wait_for_socket(listener, fn
        {:listen, %{accept_queue: [], children: children}} -> children == %{}
        _state -> false
      end)

      child_ref = Process.monitor(child)
      Process.exit(child, :kill)
      assert_receive {:DOWN, ^child_ref, :process, ^child, :killed}, 1_000

      assert wait_until(fn ->
               Tricep.Application.lookup_socket_pair(
                 {{remote_addr, @port}, {local_addr, client_port}}
               ) ==
                 nil
             end)

      _syn_ack = send_passive_syn(link, local_addr, remote_addr, client_port, client_seq + 100)
      assert Tricep.close(listener) == :ok
    end

    test "a dead finite acceptor leaves its next child supervisor-owned", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(listener, %{family: :inet6, addr: @remote_addr_str, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      acceptor = spawn(fn -> Tricep.accept(listener, 5_000) end)
      acceptor_ref = Process.monitor(acceptor)

      wait_for_socket(listener, fn
        {:listen, %{accept_waiters: [_]}} -> true
        _state -> false
      end)

      Process.exit(acceptor, :kill)
      assert_receive {:DOWN, ^acceptor_ref, :process, ^acceptor, :killed}, 1_000

      wait_for_socket(listener, fn
        {:listen, %{accept_waiters: []}} -> true
        _state -> false
      end)

      client_port = 40_041
      client_seq = 4_100
      syn_ack = send_passive_syn(link, local_addr, remote_addr, client_port, client_seq)
      send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, syn_ack.seq)

      {:listen, %{connection_supervisor: connection_supervisor}} =
        wait_for_socket(listener, fn
          {:listen, %{accept_queue: [_], pending_count: 0}} -> true
          _state -> false
        end)

      [child] = Map.keys(:sys.get_state(connection_supervisor).children)
      assert {:ok, ^child} = Tricep.accept(listener, 1_000)

      child_ref = Process.monitor(child)
      Process.exit(child, :kill)
      assert_receive {:DOWN, ^child_ref, :process, ^child, :killed}, 1_000
      assert Tricep.close(listener) == :ok
    end

    test "accept waiters settle once across timeout, caller down, and close", %{
      remote_addr: remote_addr
    } do
      parent = self()
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(listener, %{family: :inet6, addr: remote_addr, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      timeout_acceptor =
        spawn(fn -> send(parent, {:accept_result, :timeout, Tricep.accept(listener, 25)}) end)

      timeout_acceptor_ref = Process.monitor(timeout_acceptor)

      wait_for_socket(listener, fn
        {:listen, %{accept_waiters: [_]}} -> true
        _state -> false
      end)

      assert_receive {:accept_result, :timeout, {:error, :timeout}}, 1_000
      assert_receive {:DOWN, ^timeout_acceptor_ref, :process, ^timeout_acceptor, :normal}, 1_000

      wait_for_socket(listener, fn
        {:listen, %{accept_waiters: []}} -> true
        _state -> false
      end)

      refute_receive {:accept_result, :timeout, _result}, 50

      close_acceptor =
        spawn(fn -> send(parent, {:accept_result, :close, Tricep.accept(listener, 5_000)}) end)

      close_acceptor_ref = Process.monitor(close_acceptor)

      wait_for_socket(listener, fn
        {:listen, %{accept_waiters: [_]}} -> true
        _state -> false
      end)

      assert Tricep.close(listener) == :ok
      assert_receive {:accept_result, :close, {:error, :closed}}, 1_000
      assert_receive {:DOWN, ^close_acceptor_ref, :process, ^close_acceptor, :normal}, 1_000
      refute_receive {:accept_result, :close, _result}, 50
    end

    test "accept skips a stale queued child before returning a live child", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{
        listener: listener,
        child: child,
        client_port: client_port,
        client_seq: client_seq,
        syn_ack: syn_ack
      } = start_passive_child(link, local_addr, remote_addr)

      send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, syn_ack.seq)

      wait_for_socket(listener, fn
        {:listen, %{accept_queue: [_]}} -> true
        _state -> false
      end)

      prepend_stale_accepted_child(listener)

      assert {:ok, ^child} = Tricep.accept(listener, 1_000)
      assert Tricep.close(listener) == :ok
      stop_socket(child)
    end

    test "a blocking accept skips stale queued children when a live child arrives", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{
        listener: listener,
        child: child,
        client_port: client_port,
        client_seq: client_seq,
        syn_ack: syn_ack
      } = start_passive_child(link, local_addr, remote_addr)

      accept_task = Task.async(fn -> Tricep.accept(listener, 1_000) end)

      wait_for_socket(listener, fn
        {:listen, %{accept_waiters: [_]}} -> true
        _state -> false
      end)

      prepend_stale_accepted_child(listener)
      send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, syn_ack.seq)

      assert {:ok, ^child} = Task.await(accept_task, 1_000)
      assert Tricep.close(listener) == :ok
      stop_socket(child)
    end

    test "nowait accept skips stale queued children after select notification", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{
        listener: listener,
        child: child,
        client_port: client_port,
        client_seq: client_seq,
        syn_ack: syn_ack
      } = start_passive_child(link, local_addr, remote_addr)

      assert {:select, {:select_info, :accept, ref}} = Tricep.accept(listener, :nowait)
      prepend_stale_accepted_child(listener)
      send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, syn_ack.seq)

      assert_receive {:"$socket", ^listener, :select, ^ref}, 1_000
      assert {:ok, ^child} = Tricep.accept(listener, :nowait)
      assert Tricep.close(listener) == :ok
      stop_socket(child)
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

    test "listener sockname uses the public IPv6 address tuple", %{remote_addr: remote_addr} do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(listener, %{family: :inet6, addr: remote_addr, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      assert {:ok, %{family: :inet6, addr: {0xFD00, 0, 0, 0, 0, 0, 0, 2}, port: @port}} =
               Tricep.sockname(listener)

      assert Tricep.close(listener) == :ok
    end

    test "listener rejects unmodeled calls", %{remote_addr: remote_addr} do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(listener, %{family: :inet6, addr: remote_addr, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      assert {:error, :einval} = :gen_statem.call(listener, :unmodeled_listener_call)
      assert Tricep.close(listener) == :ok
    end

    test "samples passive child start failures", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(listener, %{family: :inet6, addr: remote_addr, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      {:listen, state} = :sys.get_state(listener)
      failure_supervisor = start_passive_failure_supervisor(:enomem)

      log =
        capture_log(fn ->
          state = %{state | connection_supervisor: failure_supervisor}

          state =
            Enum.reduce(1..5, state, fn _failure, state ->
              assert {:keep_state, state} =
                       Listener.handle_event(
                         :info,
                         passive_syn_event(local_addr, remote_addr, 40_099),
                         state
                       )

              state
            end)

          send(self(), {:passive_start_failure_state, state})
        end)

      assert_receive {:passive_start_failure_state, failure_state}
      assert failure_state.passive_start_failures == 5
      assert log =~ "sampled failure #1"
      assert log =~ "sampled failure #2"
      assert log =~ "sampled failure #4"
      refute log =~ "sampled failure #3"
      refute log =~ "sampled failure #5"
      assert log =~ "port: 40099"
      assert log =~ ":enomem"

      assert Tricep.close(listener) == :ok
      stop_socket(failure_supervisor)
    end

    test "keeps a closed passive child supervisor quiet", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(listener, %{family: :inet6, addr: remote_addr, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      {:listen, state} = :sys.get_state(listener)
      closed_supervisor = spawn(fn -> :ok end)
      assert wait_until(fn -> not Process.alive?(closed_supervisor) end)

      log =
        capture_log(fn ->
          state = %{state | connection_supervisor: closed_supervisor}

          assert :keep_state_and_data =
                   Listener.handle_event(
                     :info,
                     passive_syn_event(local_addr, remote_addr, 40_100),
                     state
                   )
        end)

      refute log =~ "could not start passive child"
      assert Tricep.close(listener) == :ok
    end

    test "retains queued accepts when the child supervisor is unavailable", %{
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(listener, %{family: :inet6, addr: remote_addr, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      {:listen, state} = :sys.get_state(listener)
      closed_supervisor = spawn(fn -> :ok end)
      assert wait_until(fn -> not Process.alive?(closed_supervisor) end)

      queue = [
        %Accepted{child: self()},
        %Accepted{child: spawn(fn -> :ok end)}
      ]

      from = {self(), make_ref()}
      state = %{state | connection_supervisor: closed_supervisor, accept_queue: queue}

      assert {:keep_state, retained_state, {:reply, ^from, {:error, :closed}}} =
               Listener.handle_event({:call, from}, {:accept, 1_000}, state)

      assert retained_state.accept_queue == queue
      assert Tricep.close(listener) == :ok
    end

    test "retains a finite accept waiter when the child supervisor is unavailable", %{
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(listener, %{family: :inet6, addr: remote_addr, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      {:listen, state} = :sys.get_state(listener)
      closed_supervisor = spawn(fn -> :ok end)
      assert wait_until(fn -> not Process.alive?(closed_supervisor) end)

      from = {self(), make_ref()}
      timer = make_ref()
      monitor = Process.monitor(self())
      waiter = %Waiter{from: from, id: timer, timer: timer, monitor: monitor}

      state = %{
        state
        | connection_supervisor: closed_supervisor,
          pending_count: 1,
          children: %{self() => %Child{status: :pending}},
          accept_waiters: [waiter]
      }

      assert {:keep_state, retained_state, []} =
               Listener.handle_event(:info, {:passive_established, self()}, state)

      assert retained_state.accept_waiters == [waiter]
      assert retained_state.accept_queue == [%Accepted{child: self()}]
      Process.demonitor(monitor, [:flush])
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

    test "listener close reaps an unaccepted passive child", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{listener: listener, child: child, state: state} =
        start_passive_child(link, local_addr, remote_addr)

      child_ref = Process.monitor(child)

      assert Tricep.close(listener) == :ok
      assert_receive {:DOWN, ^child_ref, :process, ^child, :shutdown}, 1_000
      refute Process.alive?(child)
      assert wait_until(fn -> Tricep.Application.lookup_listener(remote_addr, @port) == nil end)
      assert wait_until(fn -> Tricep.Application.lookup_socket_pair(state.pair) == nil end)
    end

    test "a listener survives its creator exiting normally and keeps passive children owned", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      parent = self()

      creator =
        spawn(fn ->
          {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)
          send(parent, {:listener_from_creator, self(), listener})

          receive do
            :exit_normally -> :ok
          end
        end)

      creator_ref = Process.monitor(creator)
      assert_receive {:listener_from_creator, ^creator, listener}, 1_000

      assert Tricep.bind(listener, %{family: :inet6, addr: remote_addr, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      client_port = 40_042
      client_seq = 4_200
      syn_ack = send_passive_syn(link, local_addr, remote_addr, client_port, client_seq)
      send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, syn_ack.seq)

      {:listen, %{connection_supervisor: connection_supervisor, children: children}} =
        wait_for_socket(listener, fn
          {:listen, %{children: children}} when map_size(children) == 1 -> true
          _state -> false
        end)

      [child] = Map.keys(children)
      child_ref = Process.monitor(child)

      send(creator, :exit_normally)
      assert_receive {:DOWN, ^creator_ref, :process, ^creator, :normal}, 1_000

      assert Process.alive?(listener)
      assert Tricep.Application.lookup_listener(remote_addr, @port) == listener
      assert Map.has_key?(:sys.get_state(connection_supervisor).children, child)

      assert Tricep.close(listener) == :ok
      assert_receive {:DOWN, ^child_ref, :process, ^child, :shutdown}, 1_000
    end

    test "abnormal listener shutdown reaps children without settling selectors", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{listener: listener, child: child, state: state} =
        start_passive_child(link, local_addr, remote_addr)

      assert {:select, {:select_info, :accept, ref}} = Tricep.accept(listener, :nowait)

      Process.unlink(listener)
      listener_ref = Process.monitor(listener)
      child_ref = Process.monitor(child)
      {:listen, %{connection_supervisor: connection_supervisor}} = :sys.get_state(listener)
      supervisor_ref = Process.monitor(connection_supervisor)

      Process.exit(listener, :shutdown)

      assert_receive {:DOWN, ^listener_ref, :process, ^listener, :shutdown}, 1_000
      assert_receive {:DOWN, ^child_ref, :process, ^child, :shutdown}, 1_000
      assert_receive {:DOWN, ^supervisor_ref, :process, ^connection_supervisor, :normal}, 1_000
      refute Process.alive?(child)
      refute_receive {:"$socket", ^listener, :select, ^ref}, 50
      assert wait_until(fn -> Tricep.Application.lookup_listener(remote_addr, @port) == nil end)
      assert wait_until(fn -> Tricep.Application.lookup_socket_pair(state.pair) == nil end)
    end

    test "listener kill reaps an unaccepted passive child", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{listener: listener, child: child, state: state} =
        start_passive_child(link, local_addr, remote_addr)

      Process.unlink(listener)
      listener_ref = Process.monitor(listener)
      child_ref = Process.monitor(child)

      Process.exit(listener, :kill)

      assert_receive {:DOWN, ^listener_ref, :process, ^listener, :killed}, 1_000
      assert_receive {:DOWN, ^child_ref, :process, ^child, :shutdown}, 1_000
      refute Process.alive?(child)
      assert wait_until(fn -> Tricep.Application.lookup_socket_pair(state.pair) == nil end)
    end

    test "connection supervisor kill reaps unaccepted children", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{listener: listener, child: child, state: state} =
        start_passive_child(link, local_addr, remote_addr)

      {:listen, %{connection_supervisor: connection_supervisor}} = :sys.get_state(listener)

      child_ref = Process.monitor(child)

      log =
        capture_log(fn ->
          Process.exit(connection_supervisor, :kill)

          assert_receive {:DOWN, ^child_ref, :process, ^child, :killed}, 1_000
          refute Process.alive?(child)
          assert wait_until(fn -> Tricep.Application.lookup_socket_pair(state.pair) == nil end)
          assert wait_for_state_name(listener, :closed, 1_000)
        end)

      assert log =~ "TCP listener connection supervisor exited unexpectedly: :killed"
      assert {:error, :einval} = Tricep.accept(listener, :nowait)
      assert {:error, :enotconn} = Tricep.close(listener)
    end

    test "supervisor kill closes finite accepts and preserves terminal listener APIs", %{
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(listener, %{family: :inet6, addr: remote_addr, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      accept_task = Task.async(fn -> Tricep.accept(listener, 5_000) end)

      wait_for_socket(listener, fn
        {:listen, %{accept_waiters: [_]}} -> true
        _state -> false
      end)

      assert {:select, {:select_info, :accept, ref}} = Tricep.accept(listener, :nowait)
      {:listen, %{connection_supervisor: connection_supervisor}} = :sys.get_state(listener)

      log =
        capture_log(fn ->
          Process.exit(connection_supervisor, :kill)

          assert {:error, :closed} = Task.await(accept_task, 1_000)
          assert_receive {:"$socket", ^listener, :select, ^ref}, 1_000
          assert wait_for_state_name(listener, :closed, 1_000)
        end)

      assert log =~ "TCP listener connection supervisor exited unexpectedly: :killed"
      assert {:closed, %{socket_opts: %{}}} = :sys.get_state(listener)
      assert {:error, :einval} = Tricep.accept(listener, :nowait)
      assert {:error, :enotconn} = Tricep.close(listener)
    end

    test "a queued child exit frees backlog capacity for the next SYN", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{
        listener: listener,
        child: child,
        client_port: client_port,
        client_seq: client_seq,
        syn_ack: syn_ack
      } = start_passive_child(link, local_addr, remote_addr)

      send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, syn_ack.seq)

      wait_for_socket(listener, fn
        {:listen, %{children: children, pending_count: 0, accept_queue: [_]}} ->
          Map.has_key?(children, child)

        _state ->
          false
      end)

      child_ref = Process.monitor(child)
      Process.exit(child, :kill)

      assert_receive {:DOWN, ^child_ref, :process, ^child, :killed}, 1_000

      wait_for_socket(listener, fn
        {:listen, %{children: children, pending_count: 0, accept_queue: []}} -> children == %{}
        _state -> false
      end)

      _syn_ack = send_passive_syn(link, local_addr, remote_addr, 40_021, 9_001)
      assert Tricep.close(listener) == :ok
    end

    test "ordinary close and supervisor loss use the ordinary closed contract", %{
      remote_addr: remote_addr
    } do
      {:ok, ordinary_listener} = Tricep.open(:inet6, :stream, :tcp)
      {:ok, failed_listener} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(ordinary_listener, %{family: :inet6, addr: remote_addr, port: @port}) ==
               :ok

      assert Tricep.bind(failed_listener, %{family: :inet6, addr: remote_addr, port: @port + 1}) ==
               :ok

      assert Tricep.listen(ordinary_listener, 1) == :ok
      assert Tricep.listen(failed_listener, 1) == :ok

      accept_task = Task.async(fn -> Tricep.accept(ordinary_listener, 5_000) end)

      wait_for_socket(ordinary_listener, fn
        {:listen, %{accept_waiters: [_]}} -> true
        _state -> false
      end)

      assert {:select, {:select_info, :accept, ref}} = Tricep.accept(ordinary_listener, :nowait)

      ordinary_log =
        capture_log(fn ->
          assert Tricep.close(ordinary_listener) == :ok
          assert {:error, :closed} = Task.await(accept_task, 1_000)
          assert_receive {:"$socket", ^ordinary_listener, :select, ^ref}, 1_000
        end)

      refute ordinary_log =~ "TCP listener connection supervisor"
      assert {:closed, %{}} = :sys.get_state(ordinary_listener)

      {:listen, %{connection_supervisor: connection_supervisor}} = :sys.get_state(failed_listener)

      failed_log =
        capture_log(fn ->
          Process.exit(connection_supervisor, :kill)
          assert wait_for_state_name(failed_listener, :closed, 1_000)
        end)

      assert 1 ==
               length(
                 Regex.scan(
                   ~r/TCP listener connection supervisor exited unexpectedly/,
                   failed_log
                 )
               )

      for listener <- [ordinary_listener, failed_listener] do
        assert {:error, :einval} = Tricep.accept(listener, :nowait)
        assert {:error, :enotconn} = Tricep.close(listener)
      end
    end

    test "listener termination settles pending accepts before monitor shutdown", %{
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(listener, %{family: :inet6, addr: remote_addr, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      accept_task = Task.async(fn -> Tricep.accept(listener, 5_000) end)

      wait_for_socket(listener, fn
        {:listen, %{accept_waiters: [_]}} -> true
        _state -> false
      end)

      assert {:select, {:select_info, :accept, ref}} = Tricep.accept(listener, :nowait)
      {:listen, %{connection_supervisor: connection_supervisor}} = :sys.get_state(listener)
      listener_ref = Process.monitor(listener)
      supervisor_ref = Process.monitor(connection_supervisor)

      log =
        capture_log(fn ->
          assert :ok = :gen_statem.stop(listener)
          assert {:error, :closed} = Task.await(accept_task, 1_000)
          assert_receive {:"$socket", ^listener, :select, ^ref}, 1_000
          assert_receive {:DOWN, ^listener_ref, :process, ^listener, :normal}, 1_000

          assert_receive {:DOWN, ^supervisor_ref, :process, ^connection_supervisor, :normal},
                         1_000
        end)

      refute log =~ "TCP listener connection supervisor"
      refute_receive {:"$socket", ^listener, :select, ^ref}, 50
      assert wait_until(fn -> Tricep.Application.lookup_listener(remote_addr, @port) == nil end)
    end

    test "a closed listener can rebind, relisten, and reconnect", %{
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)
      address = %{family: :inet6, addr: remote_addr, port: @port}

      assert Tricep.bind(listener, address) == :ok
      assert Tricep.listen(listener, 1) == :ok
      assert Tricep.close(listener) == :ok
      assert {:closed, %{}} = :sys.get_state(listener)

      assert Tricep.bind(listener, address) == :ok
      assert {:bound, bound_data} = :sys.get_state(listener)
      assert bound_data.local_port == @port

      assert Tricep.listen(listener, 1) == :ok
      assert Tricep.close(listener) == :ok

      assert {:select, {:select_info, :connect, _ref}} =
               Tricep.connect(
                 listener,
                 %{family: :inet6, addr: @local_addr_str, port: @port},
                 :nowait
               )

      assert_receive {:dummy_link_packet, _link, _packet}, 1_000
      assert {{:syn_sent, :nowait}, connect_state} = :sys.get_state(listener)
      assert is_map(connect_state)
      stop_socket(listener)
    end

    test "claiming an accepted child removes it from the supervisor failure domain", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{
        listener: listener,
        child: child,
        client_port: client_port,
        client_seq: client_seq,
        syn_ack: syn_ack
      } = start_passive_child(link, local_addr, remote_addr)

      {:listen, %{connection_supervisor: connection_supervisor}} = :sys.get_state(listener)
      send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, syn_ack.seq)

      assert {:established, %{passive_owner: ^connection_supervisor}} = :sys.get_state(child)

      assert {:ok, ^child} = Tricep.accept(listener, 1_000)
      assert {:established, %{passive_owner: nil}} = :sys.get_state(child)

      Process.exit(connection_supervisor, :kill)

      assert wait_for_state_name(listener, :closed, 1_000)
      assert Process.alive?(child)
      assert {:established, _state} = :sys.get_state(child)

      child_ref = Process.monitor(child)
      Process.exit(child, :kill)
      assert_receive {:DOWN, ^child_ref, :process, ^child, :killed}, 1_000
    end

    test "a peer RST reaps an established queued child before it can be accepted", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      passive = queue_passive_child(link, local_addr, remote_addr)
      child = passive.child
      child_ref = Process.monitor(child)

      inject_passive_peer_reset(local_addr, remote_addr, passive)

      assert_receive {:DOWN, ^child_ref, :process, ^child, :normal}, 1_000
      refute Process.alive?(child)
      assert_passive_child_removed(passive.listener, child)
      assert Tricep.Application.lookup_socket_pair(passive.state.pair) == nil
      refute_receive {:dummy_link_packet, ^link, _packet}, 100

      assert {:select, {:select_info, :accept, _ref}} = Tricep.accept(passive.listener, :nowait)
      assert Tricep.close(passive.listener) == :ok
    end

    test "a peer RST reaps a queued CLOSE_WAIT child before it can be accepted", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      passive = queue_close_wait_passive_child(link, local_addr, remote_addr)
      child = passive.child
      child_ref = Process.monitor(child)

      inject_passive_peer_reset(local_addr, remote_addr, passive)

      assert_receive {:DOWN, ^child_ref, :process, ^child, :normal}, 1_000
      refute Process.alive?(child)
      assert_passive_child_removed(passive.listener, child)
      assert Tricep.Application.lookup_socket_pair(passive.state.pair) == nil
      assert Tricep.close(passive.listener) == :ok
    end

    test "a blocking accept waits for a child after a queued reset", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      stale = queue_passive_child(link, local_addr, remote_addr, client_port: 40_050)
      stale_child = stale.child
      stale_ref = Process.monitor(stale_child)
      reset = passive_peer_reset(local_addr, remote_addr, stale)
      :ok = Tricep.Socket.handle_packet(local_addr, remote_addr, reset)

      assert_receive {:DOWN, ^stale_ref, :process, ^stale_child, :normal}, 1_000
      refute_receive {:dummy_link_packet, ^link, _packet}, 50

      accept_task = Task.async(fn -> Tricep.accept(stale.listener, :infinity) end)

      wait_for_socket(stale.listener, fn
        {:listen, %{accept_queue: [], accept_waiters: [_]}} -> true
        _state -> false
      end)

      live =
        establish_passive_child_on_listener(stale.listener, link, local_addr, remote_addr, 40_051)

      live_child = live.child

      assert {:ok, ^live_child} = Task.await(accept_task, 1_000)
      assert {:established, %{passive_owner: nil}} = :sys.get_state(live_child)
      assert Tricep.close(stale.listener) == :ok
      stop_socket(live_child)
    end

    test "a nowait accept does not notify until a live child is queued", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      parent = self()
      stale = queue_passive_child(link, local_addr, remote_addr, client_port: 40_052)
      stale_child = stale.child
      stale_ref = Process.monitor(stale_child)
      :ok = :sys.suspend(stale_child)

      reset = passive_peer_reset(local_addr, remote_addr, stale)
      :ok = Tricep.Socket.handle_packet(local_addr, remote_addr, reset)
      assert_socket_message_queued(stale_child, reset)

      acceptor =
        spawn(fn ->
          send(parent, {:nowait_accept_result, self(), Tricep.accept(stale.listener, :nowait)})

          receive do
            message ->
              send(parent, {:nowait_accept_notification, self(), message})

              receive do
                :stop -> :ok
              end
          end
        end)

      :ok = :sys.resume(stale_child)
      assert_receive {:DOWN, ^stale_ref, :process, ^stale_child, :normal}, 1_000

      assert_receive {:nowait_accept_result, ^acceptor, {:select, {:select_info, :accept, ref}}},
                     1_000

      refute_receive {:nowait_accept_notification, ^acceptor, _message}, 50

      live =
        establish_passive_child_on_listener(stale.listener, link, local_addr, remote_addr, 40_053)

      live_child = live.child

      assert_receive {:nowait_accept_notification, ^acceptor,
                      {:"$socket", listener, :select, ^ref}},
                     1_000

      assert listener == stale.listener
      assert {:ok, ^live_child} = Tricep.accept(stale.listener, :nowait)
      refute_receive {:nowait_accept_notification, ^acceptor, _message}, 50
      send(acceptor, :stop)
      assert Tricep.close(stale.listener) == :ok
      stop_socket(live_child)
    end

    test "a suspended queued child does not block nowait handoff", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_054)
      listener = passive.listener
      child = passive.child
      :ok = :sys.suspend(child)

      started_at = System.monotonic_time(:millisecond)
      assert {:select, {:select_info, :accept, ref}} = Tricep.accept(passive.listener, :nowait)
      assert System.monotonic_time(:millisecond) - started_at < 100

      {_handoff_id, _connection_supervisor} = wait_for_passive_handoff(passive.listener, child)
      refute_receive {:"$socket", ^listener, :select, ^ref}, 50

      :ok = :sys.resume(child)

      assert_receive {:"$socket", ^listener, :select, ^ref}, 1_000
      assert {:ok, ^child} = Tricep.accept(passive.listener, :nowait)
      assert {:established, %{passive_owner: nil}} = :sys.get_state(child)
      refute_receive {:"$socket", ^listener, :select, ^ref}, 50

      assert Tricep.close(passive.listener) == :ok
      stop_socket(child)
    end

    test "a notified nowait retry claims a suspended child locally", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_080)
      listener = passive.listener
      child = passive.child

      assert {:select, {:select_info, :accept, ref}} = Tricep.accept(listener, :nowait)
      assert_receive {:"$socket", ^listener, :select, ^ref}, 1_000
      assert_passive_child_claimed(listener, child)

      :ok = :sys.suspend(child)
      started_at = System.monotonic_time(:millisecond)
      assert {:ok, ^child} = Tricep.accept(listener, :nowait)
      assert System.monotonic_time(:millisecond) - started_at < 100

      :ok = :sys.resume(child)

      assert {:established, %{passive_owner: nil, passive_handoff: nil}} =
               wait_for_state_name(child, :established, 1_000)

      assert_passive_child_removed(listener, child)
      assert Tricep.close(listener) == :ok
      stop_socket(child)
    end

    test "a finite accept timeout cancels a suspended handoff without detaching its child", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_055)
      child = passive.child
      child_ref = Process.monitor(child)
      :ok = :sys.suspend(child)

      accept_task = Task.async(fn -> Tricep.accept(passive.listener, 50) end)
      {_handoff_id, connection_supervisor} = wait_for_passive_handoff(passive.listener, child)

      assert {:error, :timeout} = Task.await(accept_task, 1_000)
      assert_passive_child_queued(passive.listener, child)
      assert %{children: children} = :sys.get_state(connection_supervisor)
      assert %{status: :queued} = Map.fetch!(children, child)

      :ok = :sys.resume(child)

      assert {:established, %{passive_owner: ^connection_supervisor, passive_handoff: nil}} =
               wait_for_state_name(child, :established, 1_000)

      assert Tricep.close(passive.listener) == :ok
      assert_receive {:DOWN, ^child_ref, :process, ^child, :shutdown}, 1_000
    end

    test "a ready child recovers after timeout settles before its notification", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      parent = self()
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_081)
      listener = passive.listener
      child = passive.child
      :ok = :sys.suspend(child)

      acceptor =
        spawn(fn ->
          send(parent, {:timed_accept, self(), Tricep.accept(listener, 50)})

          receive do
            :stop -> :ok
          end
        end)

      {handoff_id, connection_supervisor} = wait_for_listener_handoff(listener, child)
      :ok = :sys.suspend(connection_supervisor)
      :ok = :sys.resume(child)

      assert_socket_message_queued(
        connection_supervisor,
        {:passive_handoff_prepared, child, connection_supervisor, handoff_id}
      )

      assert_receive {:timed_accept, ^acceptor, {:error, :timeout}}, 1_000
      :ok = :sys.resume(connection_supervisor)

      assert_passive_child_claimed(listener, child)
      assert_passive_ownership_invariant(listener)
      assert {:ok, ^child} = Tricep.accept(listener, :nowait)

      send(acceptor, :stop)
      assert Tricep.close(listener) == :ok
      stop_socket(child)
    end

    test "a caller down after prepare restores its child when the supervisor resumes", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_082)
      listener = passive.listener
      child = passive.child
      :ok = :sys.suspend(child)

      acceptor = spawn(fn -> Tricep.accept(listener, :infinity) end)
      acceptor_ref = Process.monitor(acceptor)
      {handoff_id, connection_supervisor} = wait_for_listener_handoff(listener, child)
      :ok = :sys.suspend(connection_supervisor)
      :ok = :sys.resume(child)

      assert_socket_message_queued(
        connection_supervisor,
        {:passive_handoff_prepared, child, connection_supervisor, handoff_id}
      )

      Process.exit(acceptor, :kill)
      assert_receive {:DOWN, ^acceptor_ref, :process, ^acceptor, :killed}, 1_000
      :ok = :sys.resume(connection_supervisor)

      assert_passive_child_queued(listener, child)
      assert_passive_ownership_invariant(listener)
      assert Tricep.close(listener) == :ok
      stop_socket(child)
    end

    test "a reset queued before a local claim returns a live closed socket", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_083)
      listener = passive.listener
      child = passive.child

      assert {:select, {:select_info, :accept, ref}} = Tricep.accept(listener, :nowait)
      assert_receive {:"$socket", ^listener, :select, ^ref}, 1_000
      assert_passive_child_claimed(listener, child)

      :ok = :sys.suspend(child)
      reset = passive_peer_reset(local_addr, remote_addr, passive)
      :ok = Tricep.Socket.handle_packet(local_addr, remote_addr, reset)
      assert_socket_message_queued(child, reset)

      assert {:ok, ^child} = Tricep.accept(listener, :nowait)
      :ok = :sys.resume(child)

      assert {:closed, %{}} = wait_for_state_name(child, :closed, 1_000)
      assert Process.alive?(child)
      assert Tricep.recv(child, 0, :nowait) == {:error, :enotconn}
      assert Tricep.send(child, "after reset", :nowait) == {:error, :enotconn}
      assert Tricep.Application.lookup_socket_pair(passive.state.pair) == nil
      assert_passive_child_removed(listener, child)

      assert Tricep.close(listener) == :ok
      stop_socket(child)
    end

    test "listener close completes while a child handoff is suspended", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_056)
      child = passive.child
      child_ref = Process.monitor(child)
      :ok = :sys.suspend(child)

      accept_task = Task.async(fn -> Tricep.accept(passive.listener, :infinity) end)
      {_handoff_id, _connection_supervisor} = wait_for_passive_handoff(passive.listener, child)

      started_at = System.monotonic_time(:millisecond)
      assert Tricep.close(passive.listener) == :ok
      assert System.monotonic_time(:millisecond) - started_at < 100
      assert {:error, :closed} = Task.await(accept_task, 1_000)
      assert_receive {:DOWN, ^child_ref, :process, ^child, :shutdown}, 1_000
    end

    test "a dead accept caller returns its suspended child to the listener", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_057)
      child = passive.child
      child_ref = Process.monitor(child)
      :ok = :sys.suspend(child)

      acceptor = spawn(fn -> Tricep.accept(passive.listener, :infinity) end)
      acceptor_ref = Process.monitor(acceptor)
      {_handoff_id, connection_supervisor} = wait_for_passive_handoff(passive.listener, child)

      Process.exit(acceptor, :kill)
      assert_receive {:DOWN, ^acceptor_ref, :process, ^acceptor, :killed}, 1_000
      assert_passive_child_queued(passive.listener, child)

      :ok = :sys.resume(child)

      assert {:established, %{passive_owner: ^connection_supervisor, passive_handoff: nil}} =
               wait_for_state_name(child, :established, 1_000)

      assert Tricep.close(passive.listener) == :ok
      assert_receive {:DOWN, ^child_ref, :process, ^child, :shutdown}, 1_000
    end

    test "listener and supervisor failure reap a suspended handoff child", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_058)
      child = passive.child
      child_ref = Process.monitor(child)
      :ok = :sys.suspend(child)

      acceptor = spawn(fn -> Tricep.accept(passive.listener, :infinity) end)
      acceptor_ref = Process.monitor(acceptor)
      {_handoff_id, connection_supervisor} = wait_for_passive_handoff(passive.listener, child)
      supervisor_ref = Process.monitor(connection_supervisor)

      Process.exit(connection_supervisor, :kill)

      assert_receive {:DOWN, ^supervisor_ref, :process, ^connection_supervisor, :killed}, 1_000
      assert_receive {:DOWN, ^child_ref, :process, ^child, :killed}, 1_000
      assert wait_for_state_name(passive.listener, :closed, 1_000)
      assert_receive {:DOWN, ^acceptor_ref, :process, ^acceptor, :normal}, 1_000
    end

    test "listener kill reaps a suspended handoff child", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_060)
      child = passive.child
      child_ref = Process.monitor(child)
      :ok = :sys.suspend(child)

      acceptor = spawn(fn -> Tricep.accept(passive.listener, :infinity) end)
      {_handoff_id, connection_supervisor} = wait_for_passive_handoff(passive.listener, child)
      supervisor_ref = Process.monitor(connection_supervisor)

      Process.unlink(passive.listener)
      listener_ref = Process.monitor(passive.listener)
      Process.exit(passive.listener, :kill)

      assert_receive {:DOWN, ^listener_ref, :process, listener, :killed}, 1_000
      assert listener == passive.listener
      assert_receive {:DOWN, ^supervisor_ref, :process, ^connection_supervisor, :normal}, 1_000
      assert_receive {:DOWN, ^child_ref, :process, ^child, :shutdown}, 1_000
      assert wait_until(fn -> Tricep.Application.lookup_listener(remote_addr, @port) == nil end)
      refute Process.alive?(acceptor)
    end

    test "a dead caller before supervisor handoff start restores its queued child", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_066)
      child = passive.child

      {:listen, %{connection_supervisor: connection_supervisor}} =
        :sys.get_state(passive.listener)

      :ok = :sys.suspend(connection_supervisor)

      acceptor = spawn(fn -> Tricep.accept(passive.listener, :infinity) end)
      acceptor_ref = Process.monitor(acceptor)
      {handoff_id, ^connection_supervisor} = wait_for_listener_handoff(passive.listener, child)

      Process.exit(acceptor, :kill)
      assert_receive {:DOWN, ^acceptor_ref, :process, ^acceptor, :killed}, 1_000

      assert_socket_message_queued(
        connection_supervisor,
        {:begin_handoff, passive.listener, handoff_id, child, acceptor}
      )

      :ok = :sys.resume(connection_supervisor)
      assert_passive_child_queued(passive.listener, child)
      assert_passive_ownership_invariant(passive.listener)
      assert Tricep.close(passive.listener) == :ok
    end

    test "forged handoff messages cannot claim a child or disclose the private token", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_067)
      child = passive.child
      :ok = :sys.suspend(child)

      assert {:select, {:select_info, :accept, select_ref}} =
               Tricep.accept(passive.listener, :nowait)

      {handoff_id, connection_supervisor} = wait_for_passive_handoff(passive.listener, child)
      refute handoff_id == select_ref

      send(passive.listener, {:passive_handoff_ready, self(), handoff_id, child})
      send(connection_supervisor, {:discard_claimed, self(), handoff_id, child})
      send(connection_supervisor, {:passive_handoff_prepared, child, self(), handoff_id})
      send(child, {:passive_handoff_prepare, self(), handoff_id})

      assert_passive_ownership_invariant(passive.listener)

      assert {:established, %{passive_owner: ^connection_supervisor, passive_handoff: nil}} =
               :sys.get_state(child)

      :ok = :sys.resume(child)
      assert_receive {:"$socket", listener, :select, ^select_ref}, 1_000
      assert listener == passive.listener
      assert {:ok, ^child} = Tricep.accept(passive.listener, :nowait)

      assert {:established, %{passive_owner: nil}} =
               wait_for_state_name(child, :established, 1_000)

      assert Tricep.close(passive.listener) == :ok
      stop_socket(child)
    end

    test "a claimed child exit immediately frees listener backlog", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      parent = self()
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_061)
      child = passive.child
      child_ref = Process.monitor(child)

      acceptor =
        spawn(fn ->
          send(parent, {:claimed_select, self(), Tricep.accept(passive.listener, :nowait)})

          receive do
            message ->
              send(parent, {:claimed_notification, self(), message})

              receive do
                :stop -> :ok
              end
          end
        end)

      assert_receive {:claimed_select, ^acceptor, {:select, {:select_info, :accept, ref}}}, 1_000

      assert_receive {:claimed_notification, ^acceptor, {:"$socket", listener, :select, ^ref}},
                     1_000

      assert listener == passive.listener

      assert_passive_child_claimed(listener, child)
      assert_passive_ownership_invariant(listener)
      Process.exit(child, :kill)
      assert_receive {:DOWN, ^child_ref, :process, ^child, :killed}, 1_000
      assert_passive_child_removed(listener, child)
      assert_passive_ownership_invariant(listener)

      replacement =
        establish_passive_child_on_listener(listener, link, local_addr, remote_addr, 40_068)

      assert_passive_child_queued(listener, replacement.child)
      assert_passive_ownership_invariant(listener)

      send(acceptor, :stop)
      assert Tricep.close(listener) == :ok
    end

    test "a select caller that dies before retry requeues its claimed child", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      parent = self()
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_062)
      child = passive.child
      child_ref = Process.monitor(child)

      acceptor =
        spawn(fn ->
          send(parent, {:claimed_select, self(), Tricep.accept(passive.listener, :nowait)})

          receive do
            message ->
              send(parent, {:claimed_notification, self(), message})

              receive do
                :stop -> :ok
              end
          end
        end)

      acceptor_ref = Process.monitor(acceptor)
      assert_receive {:claimed_select, ^acceptor, {:select, {:select_info, :accept, ref}}}, 1_000

      assert_receive {:claimed_notification, ^acceptor, {:"$socket", listener, :select, ^ref}},
                     1_000

      assert listener == passive.listener
      assert_passive_child_claimed(listener, child)

      Process.exit(acceptor, :kill)
      assert_receive {:DOWN, ^acceptor_ref, :process, ^acceptor, :killed}, 1_000
      refute_receive {:DOWN, ^child_ref, :process, ^child, _reason}, 100
      assert_passive_child_claimed(listener, child)
      assert_passive_ownership_invariant(listener)

      assert {:ok, ^child} = Tricep.accept(listener, :nowait)
      assert {:established, %{passive_owner: nil}} = :sys.get_state(child)
      assert_passive_child_removed(listener, child)
      assert Tricep.close(listener) == :ok
      stop_socket(child)
    end

    test "listener kill reaps a prepared but undelivered claimed child", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      parent = self()
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_069)
      child = passive.child
      child_ref = Process.monitor(child)

      acceptor =
        spawn(fn ->
          send(parent, {:claimed_select, self(), Tricep.accept(passive.listener, :nowait)})

          receive do
            message -> send(parent, {:claimed_notification, self(), message})
          end
        end)

      assert_receive {:claimed_select, ^acceptor, {:select, {:select_info, :accept, ref}}}, 1_000

      assert_receive {:claimed_notification, ^acceptor, {:"$socket", listener, :select, ^ref}},
                     1_000

      assert listener == passive.listener
      assert_passive_child_claimed(listener, child)
      assert_passive_ownership_invariant(listener)

      {:listen, %{connection_supervisor: connection_supervisor}} = :sys.get_state(listener)
      listener_ref = Process.monitor(listener)
      supervisor_ref = Process.monitor(connection_supervisor)
      Process.unlink(listener)
      Process.exit(listener, :kill)

      assert_receive {:DOWN, ^listener_ref, :process, ^listener, :killed}, 1_000
      assert_receive {:DOWN, ^supervisor_ref, :process, ^connection_supervisor, :normal}, 1_000
      assert_receive {:DOWN, ^child_ref, :process, ^child, :shutdown}, 1_000

      assert wait_until(fn ->
               Tricep.Application.lookup_socket_pair(passive.state.pair) == nil
             end)
    end

    test "a waiter registered during nowait handoff receives the prepared child", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      parent = self()
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_070)
      child = passive.child
      :ok = :sys.suspend(child)

      acceptor =
        spawn(fn ->
          send(parent, {:nowait_result, self(), Tricep.accept(passive.listener, :nowait)})

          receive do
            message -> send(parent, {:nowait_notification, self(), message})
          end
        end)

      assert_receive {:nowait_result, ^acceptor, {:select, {:select_info, :accept, ref}}}, 1_000
      {_handoff_id, _connection_supervisor} = wait_for_passive_handoff(passive.listener, child)

      waiter = Task.async(fn -> Tricep.accept(passive.listener, :infinity) end)

      wait_for_socket(passive.listener, fn
        {:listen, %{accept_waiters: [_]}} -> true
        _state -> false
      end)

      :ok = :sys.resume(child)

      assert_receive {:nowait_notification, ^acceptor, {:"$socket", listener, :select, ^ref}},
                     1_000

      assert listener == passive.listener
      assert {:ok, ^child} = Task.await(waiter, 1_000)
      assert {:established, %{passive_owner: nil}} = :sys.get_state(child)
      assert_passive_child_removed(passive.listener, child)
      assert Tricep.close(passive.listener) == :ok
      stop_socket(child)
    end

    test "a second select is notified when a nowait handoff becomes ready", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_071)
      child = passive.child
      :ok = :sys.suspend(child)

      assert {:select, {:select_info, :accept, first_ref}} =
               Tricep.accept(passive.listener, :nowait)

      {_handoff_id, _connection_supervisor} = wait_for_passive_handoff(passive.listener, child)

      assert {:select, {:select_info, :accept, second_ref}} =
               Tricep.accept(passive.listener, :nowait)

      :ok = :sys.resume(child)
      assert_receive {:"$socket", listener, :select, ^first_ref}, 1_000
      assert_receive {:"$socket", ^listener, :select, ^second_ref}, 1_000
      assert_passive_child_claimed(listener, child)
      assert_passive_ownership_invariant(listener)
      assert {:ok, ^child} = Tricep.accept(listener, :nowait)
      refute_receive {:"$socket", ^listener, :select, ^first_ref}, 50
      refute_receive {:"$socket", ^listener, :select, ^second_ref}, 50
      assert Tricep.close(listener) == :ok
      stop_socket(child)
    end

    test "connection supervisor close reaps a claimed child", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      parent = self()
      passive = queue_passive_child(link, local_addr, remote_addr, client_port: 40_073)
      child = passive.child
      child_ref = Process.monitor(child)

      acceptor =
        spawn(fn ->
          send(parent, {:claimed_select, self(), Tricep.accept(passive.listener, :nowait)})

          receive do
            message -> send(parent, {:claimed_notification, self(), message})
          end
        end)

      assert_receive {:claimed_select, ^acceptor, {:select, {:select_info, :accept, ref}}}, 1_000

      assert_receive {:claimed_notification, ^acceptor, {:"$socket", listener, :select, ^ref}},
                     1_000

      assert listener == passive.listener
      assert_passive_child_claimed(listener, child)
      {:listen, %{connection_supervisor: connection_supervisor}} = :sys.get_state(listener)

      assert :ok = ConnectionSupervisor.close(connection_supervisor)
      assert_receive {:DOWN, ^child_ref, :process, ^child, :shutdown}, 1_000
      assert wait_for_state_name(listener, :closed, 1_000)

      assert wait_until(fn ->
               Tricep.Application.lookup_socket_pair(passive.state.pair) == nil
             end)
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
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "corrupt data"
        )

      DummyLink.inject_packet(link, corrupt_checksum(data_segment))
      refute_receive {:dummy_link_packet, _link, _packet}, 100
      assert Tricep.recv(socket, 0, 20) == {:error, :timeout}

      {:established, after_state} = :sys.get_state(socket)
      assert after_state.tcb.rcv_nxt == state.tcb.rcv_nxt
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
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, corrupt_checksum(ack_segment))

      {:established, after_state} = :sys.get_state(socket)
      assert after_state.tcb.snd_una == state.tcb.snd_una
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

    test "caps peer MSS to the local link MSS", %{
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

      # The peer allows 1460, but the local 1500-byte link permits 1440 bytes
      # after the fixed IPv6 and TCP headers.
      # gen_statem returns {state_name, state_data}
      {:established, state} = :sys.get_state(socket)
      assert state.tcb.snd_mss == 1440
      assert state.tcb.rcv_mss == 1440

      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000
      assert Tricep.send(socket, :binary.copy("x", 1441)) == :ok

      assert_receive {:dummy_link_packet, _link, packet1}, 1000
      assert_receive {:dummy_link_packet, _link, packet2}, 1000
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      <<_::binary-size(40), segment1::binary>> = packet1
      <<_::binary-size(40), segment2::binary>> = packet2
      assert byte_size(Tcp.parse_segment(segment1).payload) == 1440
      assert byte_size(Tcp.parse_segment(segment2).payload) == 1
    end

    @tag mtu: 100_000
    test "caps maximum wire MSS to the non-jumbogram IPv6 payload ceiling", %{
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
      <<_::binary-size(40), syn_segment::binary>> = syn_packet
      syn = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment
      assert syn.options.mss == 65_515

      syn_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn.seq + 1,
          [:syn, :ack],
          65_535,
          mss: 65_535
        )

      DummyLink.inject_packet(link, syn_ack)
      assert Task.await(task, 1000) == :ok

      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert {:established, %{tcb: %{rcv_mss: 65_515, snd_mss: 65_515}}} =
               :sys.get_state(socket)

      assert Tricep.send(socket, :binary.copy("x", 65_516)) == :ok
      assert_receive {:dummy_link_packet, _link, packet1}, 1000
      assert_receive {:dummy_link_packet, _link, packet2}, 1000
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      <<_::binary-size(40), segment1::binary>> = packet1
      <<_::binary-size(40), segment2::binary>> = packet2
      assert byte_size(Tcp.parse_segment(segment1).payload) == 65_515
      assert byte_size(Tcp.parse_segment(segment2).payload) == 1
      assert Process.alive?(socket)
    end

    test "clamps zero MSS and drains the send buffer with non-empty segments", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, mss: 0)

      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000
      assert {:established, %{tcb: %{snd_mss: 48}}} = :sys.get_state(socket)

      payload = :binary.copy("x", 49)
      assert Tricep.send(socket, payload) == :ok

      assert_receive {:dummy_link_packet, _link, packet1}, 1000
      assert_receive {:dummy_link_packet, _link, packet2}, 1000
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      <<_::binary-size(40), segment1::binary>> = packet1
      <<_::binary-size(40), segment2::binary>> = packet2

      assert byte_size(Tcp.parse_segment(segment1).payload) == 48
      assert byte_size(Tcp.parse_segment(segment2).payload) == 1

      assert {:established, state} = :sys.get_state(socket)
      assert Tricep.DataBuffer.empty?(state.send_buffer)

      assert Enum.all?(state.unacked_segments, fn {_start, _end, data, _count} -> data != <<>> end)
    end

    test "clamps a one-byte peer MSS and makes finite send-buffer progress", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, mss: 1)

      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000
      assert {:established, %{tcb: %{snd_mss: 48}}} = :sys.get_state(socket)

      payload = :binary.copy("x", 49)
      assert Tricep.send(socket, payload) == :ok
      assert_receive {:dummy_link_packet, _link, packet1}, 1000
      assert_receive {:dummy_link_packet, _link, packet2}, 1000
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      <<_::binary-size(40), segment1::binary>> = packet1
      <<_::binary-size(40), segment2::binary>> = packet2
      assert byte_size(Tcp.parse_segment(segment1).payload) == 48
      assert byte_size(Tcp.parse_segment(segment2).payload) == 1

      assert {:established, state} = :sys.get_state(socket)
      assert Tricep.DataBuffer.empty?(state.send_buffer)
    end

    test "clamps only peer MSS values below the minimum send floor", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      for {peer_mss, expected_mss} <- [{47, 48}, {48, 48}, {49, 49}] do
        socket = establish_connection(link, local_addr, remote_addr, mss: peer_mss)

        assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000
        assert {:established, %{tcb: %{snd_mss: ^expected_mss}}} = :sys.get_state(socket)
      end
    end

    test "normalizes zero MSS during passive open", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)

      assert Tricep.bind(listener, %{family: :inet6, addr: @remote_addr_str, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      accept_task = Task.async(fn -> Tricep.accept(listener, 1000) end)
      client_port = 40_040
      client_seq = 6000
      syn_ack = send_passive_syn(link, local_addr, remote_addr, client_port, client_seq, 0)
      send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, syn_ack.seq)

      assert {:ok, accepted} = Task.await(accept_task, 1000)
      on_exit(fn -> stop_socket(accepted) end)

      assert {:established, %{tcb: %{snd_mss: 48}}} = :sys.get_state(accepted)
      assert Tricep.close(listener) == :ok
    end

    test "defaults to 1220 MSS when peer doesn't send MSS option", %{
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
      assert state.tcb.snd_mss == 1220
    end

    test "SYN advertises an unscaled maximum window with a non-zero scale offer" do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp, %{recv_buffer_size: 1_000_000})

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      assert_receive {:dummy_link_packet, _link, packet}, 1000

      <<_ip_header::binary-size(40), tcp_segment::binary>> = packet
      parsed = Tcp.parse_segment(tcp_segment)

      assert parsed.options.window_scale == 4
      assert parsed.window == 65_535

      Task.shutdown(task, :brutal_kill)
    end

    test "stores peer window scale from SYN-ACK without unsupported metadata", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp, %{recv_buffer_size: 1_000_000})

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
          65_535,
          window_scale: 4,
          sack_permitted: true,
          timestamp: {123, 456}
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      assert Task.await(task, 1000) == :ok

      {:established, state} = :sys.get_state(socket)

      assert state.tcb.snd_wnd_scale == 4
      assert state.tcb.rcv_wnd_scale == 4
      assert state.tcb.window_scaling_negotiated
      assert state.tcb.snd_wnd == 65_535

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
      assert Tcp.parse_segment(ack_segment).window == 62_499

      {{_, src_port}, _} = state.pair

      window_update =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack],
          10
        )

      DummyLink.inject_packet(link, window_update)
      assert {:established, %{tcb: %{snd_wnd: 160}}} = :sys.get_state(socket)

      refute Map.has_key?(state, :peer_sack_permitted)
      refute Map.has_key?(state, :peer_timestamp)
    end

    test "nowait active open disables scaling when SYN-ACK omits the option", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp, %{recv_buffer_size: 1_000_000})

      assert {:select, {:select_info, :connect, ref}} =
               Tricep.connect(
                 socket,
                 %{family: :inet6, addr: @local_addr_str, port: @port},
                 :nowait
               )

      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000
      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      assert syn.options.window_scale == 4
      assert syn.window == 65_535

      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn.seq + 1,
          [:syn, :ack],
          65_535
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      assert_receive {:"$socket", ^socket, :select, ^ref}, 1000
      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet

      assert Tcp.parse_segment(ack_segment).window == 65_535

      assert {:established, state} = :sys.get_state(socket)
      assert state.tcb.snd_wnd == 65_535
      assert state.tcb.snd_wnd_scale == 0
      assert state.tcb.rcv_wnd_scale == 0
      refute state.tcb.window_scaling_negotiated
    end

    test "blocking active open disables scaling when SYN-ACK omits the option", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp, %{recv_buffer_size: 1_000_000})

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000
      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn.seq + 1,
          [:syn, :ack],
          65_535
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      assert Task.await(task, 1000) == :ok
      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
      assert Tcp.parse_segment(ack_segment).window == 65_535

      assert {:established, state} = :sys.get_state(socket)
      assert state.tcb.rcv_wnd == 65_535
      assert state.tcb.snd_wnd_scale == 0
      assert state.tcb.rcv_wnd_scale == 0
      refute state.tcb.window_scaling_negotiated
    end

    test "nowait active open negotiates scaling and clamps the peer shift", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp, %{recv_buffer_size: 1_000_000})

      assert {:select, {:select_info, :connect, ref}} =
               Tricep.connect(
                 socket,
                 %{family: :inet6, addr: @local_addr_str, port: @port},
                 :nowait
               )

      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000
      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn.seq + 1,
          [:syn, :ack],
          65_535,
          window_scale: 255
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      assert_receive {:"$socket", ^socket, :select, ^ref}, 1000
      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
      assert Tcp.parse_segment(ack_segment).window == 62_499

      assert {:established, state} = :sys.get_state(socket)
      assert state.tcb.snd_wnd == 65_535
      assert state.tcb.snd_wnd_scale == 14
      assert state.tcb.rcv_wnd_scale == 4
      assert state.tcb.window_scaling_negotiated
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
          65_535,
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
      assert syn_ack.window == 65_535

      {:listen, listen_state} = :sys.get_state(listener)
      [child] = Map.keys(listen_state.children)

      assert {:syn_received, %{tcb: %{snd_wnd: 65_535, window_scaling_negotiated: true}}} =
               :sys.get_state(child)

      send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, syn_ack.seq)

      assert {:ok, accepted} = Tricep.accept(listener, 1000)
      on_exit(fn -> stop_socket(accepted) end)

      {:established, state} = :sys.get_state(accepted)

      assert state.tcb.snd_wnd_scale == 3
      assert state.tcb.snd_wnd == 262_144
      assert state.tcb.rcv_adv_wnd == 999_984
      assert state.tcb.rcv_wnd == 999_984
      refute Map.has_key?(state, :peer_sack_permitted)
      refute Map.has_key?(state, :peer_timestamp)

      assert Tricep.close(listener) == :ok
    end

    test "scaled receive window bounds quantization retraction and preserves entitlement", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp, %{recv_buffer_size: 1_000_000})

      assert Tricep.bind(listener, %{family: :inet6, addr: @remote_addr_str, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      client_port = 40_014
      client_seq = 0xFFFFF000

      syn =
        Tcp.build_segment(
          {{local_addr, client_port}, {remote_addr, @port}},
          client_seq,
          0,
          [:syn],
          65_535,
          window_scale: 3
        )

      DummyLink.inject_packet(link, syn)

      assert_receive {:dummy_link_packet, _link, syn_ack_packet}, 1000
      <<_ip_header::binary-size(40), syn_ack_segment::binary>> = syn_ack_packet
      syn_ack = Tcp.parse_segment(syn_ack_segment)

      send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, syn_ack.seq)

      assert {:ok, accepted} = Tricep.accept(listener, 1000)
      on_exit(fn -> stop_socket(accepted) end)

      assert {:established, initial_state} = :sys.get_state(accepted)
      assert initial_state.tcb.rcv_adv_wnd == 999_984
      assert initial_state.tcb.rcv_wnd == 999_984

      initial_offered_edge = wrap_seq(initial_state.tcb.rcv_nxt + initial_state.tcb.rcv_adv_wnd)

      {buffered_state, final_offered_edge, saw_retraction, _authorized_edge} =
        Enum.reduce(
          1..66,
          {initial_state, initial_offered_edge, false, initial_state.tcb.rcv_right_edge},
          fn _, {state, previous_edge, saw_retraction, previous_authorized_edge} ->
            # 1000 is intentionally not a multiple of the scale-4 quantum.
            payload = :binary.copy("x", 1000)

            data_segment =
              Tcp.build_segment(
                {{local_addr, client_port}, {remote_addr, @port}},
                state.tcb.rcv_nxt,
                state.tcb.snd_nxt,
                [:ack, :psh],
                32_768,
                payload: payload
              )

            DummyLink.inject_packet(link, data_segment)

            assert_receive {:dummy_link_packet, _link, data_ack_packet}, 1000
            <<_ip_header::binary-size(40), data_ack_segment::binary>> = data_ack_packet
            data_ack = Tcp.parse_segment(data_ack_segment)

            offered_edge =
              wrap_seq(data_ack.ack + Bitwise.bsl(data_ack.window, state.tcb.rcv_wnd_scale))

            forward_delta = Bitwise.band(offered_edge - previous_edge, 0xFFFFFFFF)
            retraction = Bitwise.band(previous_edge - offered_edge, 0xFFFFFFFF)
            retracted? = forward_delta >= 0x80000000

            if retracted?, do: assert(retraction <= 15)

            assert {:established, new_state} = :sys.get_state(accepted)

            assert new_state.tcb.rcv_wnd <=
                     new_state.recv_buffer_size - byte_size(new_state.recv_buffer)

            assert new_state.tcb.rcv_adv_wnd <=
                     new_state.recv_buffer_size - byte_size(new_state.recv_buffer)

            assert Bitwise.band(
                     new_state.tcb.rcv_right_edge - previous_authorized_edge,
                     0xFFFFFFFF
                   ) <
                     0x80000000

            {new_state, offered_edge, saw_retraction or retracted?, new_state.tcb.rcv_right_edge}
          end
        )

      assert byte_size(buffered_state.recv_buffer) == 66_000
      assert saw_retraction

      assert Bitwise.band(buffered_state.tcb.rcv_right_edge - final_offered_edge, 0xFFFFFFFF) <
               0x80000000

      assert {:ok, drained} = Tricep.recv(accepted, 16, 1000)
      assert drained == :binary.copy("x", 16)

      assert_receive {:dummy_link_packet, _link, update_packet}, 1000
      <<_ip_header::binary-size(40), update_segment::binary>> = update_packet
      update = Tcp.parse_segment(update_segment)
      assert update.window == 58_376

      update_edge =
        wrap_seq(update.ack + Bitwise.bsl(update.window, buffered_state.tcb.rcv_wnd_scale))

      assert Bitwise.band(update_edge - final_offered_edge, 0xFFFFFFFF) < 0x80000000

      {:established, reopened_state} = :sys.get_state(accepted)
      assert reopened_state.tcb.rcv_adv_wnd == 934_016

      assert reopened_state.tcb.rcv_wnd <=
               reopened_state.recv_buffer_size - byte_size(reopened_state.recv_buffer)

      assert Tricep.close(listener) == :ok
    end

    test "out-of-order buffering retracts the encoded edge only to physical capacity", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket =
        establish_connection(link, local_addr, remote_addr,
          open_opts: %{recv_buffer_size: 1_000_000},
          window_scale: 0
        )

      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, _link, _handshake_ack_packet}, 1000

      assert {:established, initial_state} = :sys.get_state(socket)
      assert initial_state.tcb.rcv_wnd_scale == 4
      {{_, src_port}, _} = initial_state.pair

      initial_edge = wrap_seq(initial_state.tcb.rcv_nxt + initial_state.tcb.rcv_adv_wnd)

      out_of_order_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(initial_state.tcb.rcv_nxt + 500_000),
          initial_state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: :binary.copy("o", 1440)
        )

      DummyLink.inject_packet(link, out_of_order_segment)
      assert_receive {:dummy_link_packet, _link, duplicate_ack_packet}, 1000
      <<_ip_header::binary-size(40), duplicate_ack_segment::binary>> = duplicate_ack_packet
      duplicate_ack = Tcp.parse_segment(duplicate_ack_segment)
      assert duplicate_ack.ack == initial_state.tcb.rcv_nxt

      encoded_edge =
        wrap_seq(
          duplicate_ack.ack +
            Bitwise.bsl(duplicate_ack.window, initial_state.tcb.rcv_wnd_scale)
        )

      retraction = Bitwise.band(initial_edge - encoded_edge, 0xFFFFFFFF)
      assert retraction > 15
      assert retraction <= 1440

      assert {:established, buffered_state} = :sys.get_state(socket)

      available =
        buffered_state.recv_buffer_size -
          byte_size(buffered_state.recv_buffer) -
          Enum.sum(
            Enum.map(buffered_state.out_of_order_segments, fn {_seq, _seq_end, payload} ->
              byte_size(payload)
            end)
          )

      assert length(buffered_state.out_of_order_segments) == 1
      assert buffered_state.tcb.rcv_adv_wnd <= available
      assert buffered_state.tcb.rcv_wnd <= available
      assert buffered_state.tcb.rcv_right_edge == initial_state.tcb.rcv_right_edge
    end

    test "scaled zero window retains an already-authorized byte and FIN", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp, %{recv_buffer_size: 65_536})

      assert Tricep.bind(listener, %{family: :inet6, addr: @remote_addr_str, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      client_port = 40_015
      client_seq = 11_000

      syn =
        Tcp.build_segment(
          {{local_addr, client_port}, {remote_addr, @port}},
          client_seq,
          0,
          [:syn],
          65_535,
          window_scale: 0
        )

      DummyLink.inject_packet(link, syn)
      assert_receive {:dummy_link_packet, _link, syn_ack_packet}, 1000
      <<_ip_header::binary-size(40), syn_ack_segment::binary>> = syn_ack_packet
      syn_ack = Tcp.parse_segment(syn_ack_segment)
      assert syn_ack.options.window_scale == 1

      send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, syn_ack.seq)
      assert {:ok, accepted} = Tricep.accept(listener, 1000)
      on_exit(fn -> stop_socket(accepted) end)

      {:established, initial_state} = :sys.get_state(accepted)

      almost_closed_state =
        Enum.reduce_while(1..100, initial_state, fn _, state ->
          if state.tcb.rcv_adv_wnd == 2 do
            {:halt, state}
          else
            chunk_size = min(1440, state.tcb.rcv_adv_wnd - 2)

            data_segment =
              Tcp.build_segment(
                {{local_addr, client_port}, {remote_addr, @port}},
                state.tcb.rcv_nxt,
                state.tcb.snd_nxt,
                [:ack, :psh],
                32_768,
                payload: :binary.copy("z", chunk_size)
              )

            DummyLink.inject_packet(link, data_segment)
            assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
            <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
            assert Tcp.parse_segment(ack_segment).window > 0
            assert {:established, new_state} = :sys.get_state(accepted)
            {:cont, new_state}
          end
        end)

      assert almost_closed_state.tcb.rcv_adv_wnd == 2

      one_byte = fn state ->
        segment =
          Tcp.build_segment(
            {{local_addr, client_port}, {remote_addr, @port}},
            state.tcb.rcv_nxt,
            state.tcb.snd_nxt,
            [:ack, :psh],
            32_768,
            payload: "z"
          )

        DummyLink.inject_packet(link, segment)
        assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
        <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
        {Tcp.parse_segment(ack_segment), :sys.get_state(accepted)}
      end

      {zero_ack, {:established, zero_state}} = one_byte.(almost_closed_state)
      assert zero_ack.window == 0
      assert zero_state.tcb.rcv_adv_wnd == 0
      assert zero_state.tcb.rcv_wnd == 1

      assert zero_state.tcb.rcv_wnd <=
               zero_state.recv_buffer_size - byte_size(zero_state.recv_buffer)

      fin_segment =
        Tcp.build_segment(
          {{local_addr, client_port}, {remote_addr, @port}},
          zero_state.tcb.rcv_nxt,
          zero_state.tcb.snd_nxt,
          [:fin, :ack],
          32_768
        )

      DummyLink.inject_packet(link, fin_segment)
      assert_receive {:dummy_link_packet, _link, final_ack_packet}, 1000
      <<_ip_header::binary-size(40), final_ack_segment::binary>> = final_ack_packet
      assert Tcp.parse_segment(final_ack_segment).window == 0

      assert {:close_wait, final_state} = :sys.get_state(accepted)
      assert final_state.tcb.rcv_adv_wnd == 0
      assert final_state.tcb.rcv_wnd == 0
      assert final_state.fin_received
      assert byte_size(final_state.recv_buffer) == 65_535

      assert Tricep.close(listener) == :ok
    end

    test "bare FIN at RCV.NXT closes a completely full zero window", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      for {buffer_size, peer_window_scale} <- [{65_535, nil}, {65_536, 0}] do
        opts = [open_opts: %{recv_buffer_size: buffer_size}]

        opts =
          if is_nil(peer_window_scale),
            do: opts,
            else: Keyword.put(opts, :window_scale, peer_window_scale)

        socket = establish_connection(link, local_addr, remote_addr, opts)
        on_exit(fn -> stop_socket(socket) end)

        # Drain the active opener's final handshake ACK.
        assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

        {:established, initial_state} = :sys.get_state(socket)
        {{_, src_port}, _} = initial_state.pair

        full_state =
          Enum.reduce_while(1..100, initial_state, fn _, state ->
            remaining = buffer_size - byte_size(state.recv_buffer)

            if remaining == 0 do
              {:halt, state}
            else
              chunk_size = min(1440, min(remaining, state.tcb.rcv_wnd))
              assert chunk_size > 0

              data_segment =
                Tcp.build_segment(
                  {{local_addr, @port}, {remote_addr, src_port}},
                  state.tcb.rcv_nxt,
                  state.tcb.snd_nxt,
                  [:ack, :psh],
                  32_768,
                  payload: :binary.copy("f", chunk_size)
                )

              DummyLink.inject_packet(link, data_segment)
              assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
              <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet

              assert Tcp.parse_segment(ack_segment).ack ==
                       wrap_seq(state.tcb.rcv_nxt + chunk_size)

              assert {:established, next_state} = :sys.get_state(socket)
              {:cont, next_state}
            end
          end)

        assert byte_size(full_state.recv_buffer) == buffer_size
        assert full_state.tcb.rcv_wnd == 0
        assert full_state.tcb.rcv_adv_wnd == 0

        rejected_data =
          Tcp.build_segment(
            {{local_addr, @port}, {remote_addr, src_port}},
            full_state.tcb.rcv_nxt,
            full_state.tcb.snd_nxt,
            [:ack, :psh],
            32_768,
            payload: "x"
          )

        DummyLink.inject_packet(link, rejected_data)
        assert_receive {:dummy_link_packet, _link, zero_window_ack_packet}, 1000
        <<_ip_header::binary-size(40), zero_window_ack_segment::binary>> = zero_window_ack_packet
        zero_window_ack = Tcp.parse_segment(zero_window_ack_segment)
        assert zero_window_ack.ack == full_state.tcb.rcv_nxt
        assert zero_window_ack.window == 0
        assert {:established, rejected_state} = :sys.get_state(socket)
        assert rejected_state.tcb.rcv_nxt == full_state.tcb.rcv_nxt
        assert rejected_state.recv_buffer == full_state.recv_buffer

        fin_without_ack =
          Tcp.build_segment(
            {{local_addr, @port}, {remote_addr, src_port}},
            full_state.tcb.rcv_nxt,
            full_state.tcb.snd_nxt,
            [:fin],
            32_768
          )

        DummyLink.inject_packet(link, fin_without_ack)
        assert_receive {:dummy_link_packet, _link, rejected_fin_ack_packet}, 1000

        <<_ip_header::binary-size(40), rejected_fin_ack_segment::binary>> =
          rejected_fin_ack_packet

        rejected_fin_ack = Tcp.parse_segment(rejected_fin_ack_segment)
        assert rejected_fin_ack.ack == full_state.tcb.rcv_nxt
        assert rejected_fin_ack.window == 0
        assert {:established, no_ack_fin_state} = :sys.get_state(socket)
        refute no_ack_fin_state.fin_received
        assert no_ack_fin_state.recv_buffer == full_state.recv_buffer

        fin_segment =
          Tcp.build_segment(
            {{local_addr, @port}, {remote_addr, src_port}},
            full_state.tcb.rcv_nxt,
            full_state.tcb.snd_nxt,
            [:fin, :ack],
            32_768
          )

        DummyLink.inject_packet(link, fin_segment)
        assert_receive {:dummy_link_packet, _link, fin_ack_packet}, 1000
        <<_ip_header::binary-size(40), fin_ack_segment::binary>> = fin_ack_packet
        assert Tcp.parse_segment(fin_ack_segment).ack == wrap_seq(full_state.tcb.rcv_nxt + 1)

        assert {:close_wait, close_wait_state} = :sys.get_state(socket)
        assert close_wait_state.fin_received
        assert byte_size(close_wait_state.recv_buffer) == buffer_size

        assert {:ok, drained} = Tricep.recv(socket, 0, 1000)
        assert byte_size(drained) == buffer_size
        assert_receive {:dummy_link_packet, _link, _window_update_packet}, 1000
        assert {:ok, <<>>} = Tricep.recv(socket, 0, 1000)
      end
    end

    test "passive open omits window scale when the SYN omits it", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp, %{recv_buffer_size: 1_000_000})

      assert Tricep.bind(listener, %{family: :inet6, addr: @remote_addr_str, port: @port}) == :ok
      assert Tricep.listen(listener, 1) == :ok

      client_port = 40_011
      client_seq = 9001

      syn =
        Tcp.build_segment(
          {{local_addr, client_port}, {remote_addr, @port}},
          client_seq,
          0,
          [:syn],
          65_535,
          mss: 1000
        )

      DummyLink.inject_packet(link, syn)

      assert_receive {:dummy_link_packet, _link, syn_ack_packet}, 1000
      <<_ip_header::binary-size(40), syn_ack_segment::binary>> = syn_ack_packet
      syn_ack = Tcp.parse_segment(syn_ack_segment)

      refute Map.has_key?(syn_ack.options, :window_scale)
      assert syn_ack.window == 65_535

      {:listen, listen_state} = :sys.get_state(listener)
      [child] = Map.keys(listen_state.children)

      assert {:syn_received, state} = :sys.get_state(child)
      assert state.tcb.snd_wnd == 65_535
      assert state.tcb.snd_wnd_scale == 0
      assert state.tcb.rcv_wnd_scale == 0
      refute state.tcb.window_scaling_negotiated

      send_passive_ack(link, local_addr, remote_addr, client_port, client_seq, syn_ack.seq)

      assert {:ok, accepted} = Tricep.accept(listener, 1000)
      on_exit(fn -> stop_socket(accepted) end)

      assert {:established, %{tcb: %{snd_wnd: 32_768}}} = :sys.get_state(accepted)
      assert Tricep.close(listener) == :ok
    end

    test "passive SYN-ACK retransmission preserves negotiated option presence", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, listener} = Tricep.open(:inet6, :stream, :tcp, %{recv_buffer_size: 1_000_000})

      assert Tricep.bind(listener, %{family: :inet6, addr: @remote_addr_str, port: @port}) == :ok
      assert Tricep.listen(listener, 2) == :ok

      for {client_port, options} <- [{40_012, [window_scale: 3]}, {40_013, []}] do
        syn =
          Tcp.build_segment(
            {{local_addr, client_port}, {remote_addr, @port}},
            9000 + client_port,
            0,
            [:syn],
            65_535,
            options
          )

        DummyLink.inject_packet(link, syn)
        assert_receive {:dummy_link_packet, _link, _initial_syn_ack}, 1000
      end

      retransmissions =
        for _ <- 1..2 do
          assert_receive {:dummy_link_packet, _link, packet}, 1500
          packet
        end

      retransmissions_by_port =
        Map.new(retransmissions, fn packet ->
          <<_ip_header::binary-size(40), tcp_segment::binary>> = packet
          <<_src_port::16, dst_port::16, _rest::binary>> = tcp_segment

          {dst_port, Tcp.parse_segment(tcp_segment)}
        end)

      assert retransmissions_by_port[40_012].options.window_scale == 4
      refute Map.has_key?(retransmissions_by_port[40_013].options, :window_scale)
      assert retransmissions_by_port[40_012].window == 65_535
      assert retransmissions_by_port[40_013].window == 65_535

      assert Tricep.close(listener) == :ok
    end
  end

  describe "SYN_RECEIVED admission" do
    test "keeps applicable ICMPv6 hard errors soft during the passive handshake", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{listener: listener, child: child, state: state} =
        start_passive_child(link, local_addr, remote_addr)

      send(child, {
        :icmpv6_error,
        {:hard, :enetunreach},
        %{seq: state.tcb.snd_nxt, syn?: true}
      })

      assert {:syn_received, %{syn_retransmit_count: 0, soft_error: nil}} = :sys.get_state(child)

      send(child, {:icmpv6_error, {:hard, :enetunreach}, %{seq: state.tcb.iss, syn?: true}})

      wait_for_socket(child, fn
        {:syn_received, %{syn_retransmit_count: 0, soft_error: :enetunreach}} -> true
        _state -> false
      end)

      assert_receive {:dummy_link_packet, ^link, _syn_ack_retransmission}, 1500

      assert {:syn_received, %{syn_retransmit_count: 1, soft_error: :enetunreach}} =
               :sys.get_state(child)

      assert Tricep.close(listener) == :ok
    end

    test "reports a valid passive-handshake ICMP error after SYN-ACK retries exhaust", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{listener: listener, child: child, state: state, syn_ack_timer_ref: timer_ref} =
        start_passive_child_with_syn_ack_timer(link, local_addr, remote_addr)

      child_ref = Process.monitor(child)

      log =
        capture_log([level: :debug], fn ->
          exhaust_syn_ack_retries(child, timer_ref, {:hard, :enetunreach}, %{
            seq: state.tcb.iss,
            syn?: true
          })

          assert_receive {:DOWN, ^child_ref, :process, ^child, :normal}, 1_500
          refute Process.alive?(child)

          wait_for_socket(listener, fn
            {:listen, %{children: children, pending_count: 0, accept_queue: []}} ->
              children == %{}

            _state ->
              false
          end)
        end)

      assert log =~ "[debug] Passive TCP handshake failed after SYN-ACK retry exhaustion"
      assert log =~ ":enetunreach"
      assert Tricep.close(listener) == :ok
    end

    test "does not retain an invalid passive-handshake ICMP error for retry exhaustion", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{listener: listener, child: child, state: state, syn_ack_timer_ref: timer_ref} =
        start_passive_child_with_syn_ack_timer(link, local_addr, remote_addr)

      child_ref = Process.monitor(child)

      log =
        capture_log([level: :debug], fn ->
          exhaust_syn_ack_retries(child, timer_ref, {:hard, :enetunreach}, %{
            seq: state.tcb.snd_nxt,
            syn?: true
          })

          assert_receive {:DOWN, ^child_ref, :process, ^child, :normal}, 1_500
          refute Process.alive?(child)

          wait_for_socket(listener, fn
            {:listen, %{children: children, pending_count: 0, accept_queue: []}} ->
              children == %{}

            _state ->
              false
          end)
        end)

      assert log =~ "[debug] Passive TCP handshake failed after SYN-ACK retry exhaustion"
      assert log =~ ":etimedout"
      refute log =~ "retry exhaustion: :enetunreach"
      assert Tricep.close(listener) == :ok
    end

    test "terminates a pending child on an acceptable reset", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{listener: listener, child: child, client_port: client_port, state: state} =
        start_passive_child(link, local_addr, remote_addr)

      child_ref = Process.monitor(child)

      reset =
        Tcp.build_segment(
          {{local_addr, client_port}, {remote_addr, @port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:rst],
          0
        )

      send(child, reset)

      assert_receive {:DOWN, ^child_ref, :process, ^child, :normal}, 1_000
      refute Process.alive?(child)

      wait_for_socket(listener, fn
        {:listen, %{children: children, pending_count: 0, accept_queue: []}} -> children == %{}
        _state -> false
      end)

      assert Tricep.close(listener) == :ok
    end

    test "queues sequence-acceptable reordered data while completing the handshake", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{listener: listener, child: child, client_port: client_port, state: state} =
        start_passive_child(link, local_addr, remote_addr)

      payload = "reordered"
      sequence = wrap_seq(state.tcb.rcv_nxt + 7)

      segment =
        Tcp.build_segment(
          {{local_addr, client_port}, {remote_addr, @port}},
          sequence,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: payload
        )

      DummyLink.inject_packet(link, segment)

      assert_receive {:dummy_link_packet, ^link, ack_packet}, 1000
      <<_::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert ack.flags == [:ack]
      assert ack.ack == state.tcb.rcv_nxt
      refute :rst in ack.flags

      assert {:established, established_state} = :sys.get_state(child)
      assert established_state.tcb.rcv_nxt == state.tcb.rcv_nxt

      assert established_state.out_of_order_segments == [
               {sequence, wrap_seq(sequence + byte_size(payload)), payload}
             ]

      assert {:ok, ^child} = Tricep.accept(listener, 1000)
      assert Tricep.close(listener) == :ok
      stop_socket(child)
    end

    test "retains a queued FIN while completing the passive handshake", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{listener: listener, child: child, client_port: client_port, state: state} =
        start_passive_child(link, local_addr, remote_addr)

      queued_fin =
        Tcp.build_segment(
          {{local_addr, client_port}, {remote_addr, @port}},
          wrap_seq(state.tcb.rcv_nxt + 5),
          state.tcb.snd_nxt,
          [:ack, :fin],
          32_768,
          payload: "world"
        )

      DummyLink.inject_packet(link, queued_fin)

      assert_receive {:dummy_link_packet, ^link, queued_ack_packet}, 1000
      <<_::binary-size(40), queued_ack_segment::binary>> = queued_ack_packet
      queued_ack = Tcp.parse_segment(queued_ack_segment)

      assert queued_ack.flags == [:ack]
      assert queued_ack.seq == state.tcb.snd_nxt
      assert queued_ack.ack == state.tcb.rcv_nxt
      assert queued_ack.window == state.tcb.rcv_adv_wnd - 5
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:established, queued_state} = :sys.get_state(child)

      assert queued_state.out_of_order_segments == [
               {state.tcb.rcv_nxt + 5, state.tcb.rcv_nxt + 10, "world"}
             ]

      assert queued_state.out_of_order_fin == state.tcb.rcv_nxt + 10

      gap_segment =
        Tcp.build_segment(
          {{local_addr, client_port}, {remote_addr, @port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: "hello"
        )

      DummyLink.inject_packet(link, gap_segment)
      assert_receive {:dummy_link_packet, ^link, fin_ack_packet}, 1000
      <<_::binary-size(40), fin_ack_segment::binary>> = fin_ack_packet
      fin_ack = Tcp.parse_segment(fin_ack_segment)

      assert fin_ack.flags == [:ack]
      assert fin_ack.seq == state.tcb.snd_nxt
      assert fin_ack.ack == wrap_seq(state.tcb.rcv_nxt + 11)
      assert fin_ack.window == state.tcb.rcv_adv_wnd - 10
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:close_wait, _} = :sys.get_state(child)
      assert {:ok, ^child} = Tricep.accept(listener, 1000)
      assert Tricep.recv(child, 0, 1000) == {:ok, "helloworld"}
      assert Tricep.recv(child, 0, 1000) == {:ok, <<>>}

      assert Tricep.close(listener) == :ok
      stop_socket(child)
    end

    test "processes a final ACK carrying an in-order FIN before accept", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{listener: listener, child: child, client_port: client_port, state: state} =
        start_passive_child(link, local_addr, remote_addr)

      final_ack_and_fin =
        Tcp.build_segment(
          {{local_addr, client_port}, {remote_addr, @port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :fin],
          32_768
        )

      DummyLink.inject_packet(link, final_ack_and_fin)

      assert_receive {:dummy_link_packet, ^link, response_packet}, 1000
      <<_::binary-size(40), response_segment::binary>> = response_packet
      response = Tcp.parse_segment(response_segment)

      assert response.flags == [:ack]
      assert response.seq == state.tcb.snd_nxt
      assert response.ack == wrap_seq(state.tcb.rcv_nxt + 1)
      assert response.window == 65_535
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:close_wait, close_wait_state} = :sys.get_state(child)
      assert close_wait_state.fin_received
      assert {:ok, ^child} = Tricep.accept(listener, 1000)
      assert Tricep.recv(child, 0, 1000) == {:ok, <<>>}

      assert Tricep.close(listener) == :ok
      stop_socket(child)
    end

    test "drops an out-of-window ACK and data without generating RST", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{listener: listener, child: child, client_port: client_port, state: state} =
        start_passive_child(link, local_addr, remote_addr)

      out_of_window = wrap_seq(state.tcb.rcv_nxt + state.tcb.rcv_wnd)

      segment =
        Tcp.build_segment(
          {{local_addr, client_port}, {remote_addr, @port}},
          out_of_window,
          wrap_seq(state.tcb.snd_nxt + 1),
          [:ack, :psh],
          32_768,
          payload: "old"
        )

      DummyLink.inject_packet(link, segment)

      assert_receive {:dummy_link_packet, ^link, rejection_packet}, 1000
      <<_::binary-size(40), rejection_segment::binary>> = rejection_packet
      rejection = Tcp.parse_segment(rejection_segment)

      assert rejection.flags == [:ack]
      assert rejection.ack == state.tcb.rcv_nxt
      refute :rst in rejection.flags
      assert {:syn_received, ^state} = :sys.get_state(child)

      assert Tricep.close(listener) == :ok
      stop_socket(child)
    end

    test "only resets sequence-acceptable ACKs outside the SYN-ACK range at wrap", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      %{listener: listener, child: child, client_port: client_port, state: state} =
        start_passive_child(link, local_addr, remote_addr, client_seq: 0xFFFFFFFF)

      assert state.tcb.rcv_nxt == 0

      invalid_ack =
        Tcp.build_segment(
          {{local_addr, client_port}, {remote_addr, @port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_una,
          [:ack],
          32_768
        )

      DummyLink.inject_packet(link, invalid_ack)

      assert_receive {:dummy_link_packet, ^link, rst_packet}, 1000
      <<_::binary-size(40), rst_segment::binary>> = rst_packet
      rst = Tcp.parse_segment(rst_segment)

      assert rst.flags == [:rst]
      assert rst.seq == state.tcb.snd_una
      assert {:syn_received, ^state} = :sys.get_state(child)

      stale_ack =
        Tcp.build_segment(
          {{local_addr, client_port}, {remote_addr, @port}},
          0xFFFFFFFF,
          state.tcb.snd_una,
          [:ack],
          32_768
        )

      DummyLink.inject_packet(link, stale_ack)

      assert_receive {:dummy_link_packet, ^link, rejection_packet}, 1000
      <<_::binary-size(40), rejection_segment::binary>> = rejection_packet
      rejection = Tcp.parse_segment(rejection_segment)

      assert rejection.flags == [:ack]
      refute :rst in rejection.flags
      assert {:syn_received, ^state} = :sys.get_state(child)

      assert Tricep.close(listener) == :ok
      stop_socket(child)
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
      socket = establish_connection(link, local_addr, remote_addr, mss: 48)

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Send data larger than MSS
      payload = :binary.copy("x", 49)
      assert Tricep.send(socket, payload) == :ok

      # Should receive two segments
      assert_receive {:dummy_link_packet, _link, packet1}, 1000
      assert_receive {:dummy_link_packet, _link, packet2}, 1000

      <<_::binary-size(40), seg1::binary>> = packet1
      <<_::binary-size(40), seg2::binary>> = packet2

      parsed1 = Tcp.parse_segment(seg1)
      parsed2 = Tcp.parse_segment(seg2)

      assert byte_size(parsed1.payload) == 48
      assert byte_size(parsed2.payload) == 1
    end

    test "limits sent data to the peer receive window and resumes after ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, mss: 48, window: 1)

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
          state.tcb.irs + 1,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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

    test "bounds total send ownership and wakes a selector after ACK drain", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket =
        establish_connection(link, local_addr, remote_addr,
          window: 4,
          open_opts: %{send_buffer_size: 4, send_buffer_low_watermark: 2}
        )

      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000
      assert Tricep.send(socket, "abcd") == :ok
      assert_receive {:dummy_link_packet, ^link, packet}, 1000

      <<_::binary-size(40), segment::binary>> = packet
      sent = Tcp.parse_segment(segment)
      assert sent.payload == "abcd"

      assert {:select, {:select_info, :send, ref}} = Tricep.send(socket, "e", :nowait)
      assert {:established, full_state} = :sys.get_state(socket)
      assert Tricep.DataBuffer.size(full_state.send_buffer) == 0
      assert [{_start, _ending, "abcd", 0}] = full_state.unacked_segments
      assert length(full_state.send_waiters) == 1

      {{_, source_port}, _} = full_state.pair

      ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, source_port}},
          full_state.tcb.irs + 1,
          sent.seq + byte_size(sent.payload),
          [:ack],
          4
        )

      DummyLink.inject_packet(link, ack)
      assert_receive {:"$socket", ^socket, :select, ^ref}, 1000
      assert Tricep.send(socket, "e", :nowait) == :ok
      assert_receive {:dummy_link_packet, ^link, drained_packet}, 1000
      <<_::binary-size(40), drained_segment::binary>> = drained_packet
      assert Tcp.parse_segment(drained_segment).payload == "e"
    end

    test "queues a full-size blocking write until ACK drain", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 65_535)
      first_write = :binary.copy("a", 32_768)
      second_write = :binary.copy("b", 32_768)

      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000
      assert Tricep.send(socket, first_write) == :ok

      {:established, first_state} =
        wait_for_socket(socket, fn
          {:established, state} ->
            Enum.reduce(state.unacked_segments, 0, fn {_start, _end, payload, _count}, total ->
              total + byte_size(payload)
            end) == byte_size(first_write)

          _ ->
            false
        end)

      second_task = Task.async(fn -> Tricep.send(socket, second_write, :infinity) end)
      wait_for_send_waiters(socket)

      assert {:established, waiting_state} = :sys.get_state(socket)
      assert [{:wait, _from, ^second_write, nil, _monitor_ref}] = waiting_state.send_waiters

      owned_bytes =
        Enum.reduce(waiting_state.unacked_segments, 0, fn {_start, _end, payload, _count},
                                                          total ->
          total + byte_size(payload)
        end)

      assert owned_bytes == byte_size(first_write)
      assert byte_size(second_write) <= waiting_state.send_buffer_size
      assert owned_bytes + byte_size(second_write) > waiting_state.send_buffer_size
      assert length(waiting_state.send_waiters) <= waiting_state.send_waiter_limit

      assert owned_bytes + byte_size(second_write) <=
               waiting_state.send_buffer_size +
                 waiting_state.send_waiter_limit * waiting_state.send_buffer_size

      {{_, source_port}, _} = first_state.pair

      ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, source_port}},
          first_state.tcb.irs + 1,
          first_state.tcb.snd_nxt,
          [:ack],
          65_535
        )

      DummyLink.inject_packet(link, ack)
      assert Task.await(second_task, 1_000) == :ok
    end

    test "preserves retransmit budget while a saturated link rejects data", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000
      assert Tricep.send(socket, "payload") == :ok
      assert_receive {:dummy_link_packet, ^link, _data_packet}, 1000

      {:established, state} =
        wait_for_socket(socket, fn
          {:established, %{unacked_segments: [{_seq, _end, "payload", 0}]}} -> true
          _ -> false
        end)

      :ok = DummyLink.clear_packets(link)
      :ok = DummyLink.set_send_result(link, {:error, :eagain})

      {stalled_state, deadline} =
        Enum.reduce(1..6, {state, nil}, fn _attempt, {current_state, deadline} ->
          rto_ms = current_state.rto_ms
          retry_ms = current_state.link_retry_ms

          retry_result =
            if current_state.link_retry_path do
              Tricep.Socket.retry_link_retransmit(current_state)
            else
              Tricep.Socket.do_retransmit(current_state)
            end

          assert {:keep_state, retry_state,
                  {{:timeout, :link_retry}, ^retry_ms, {:retry, :retransmit}}} = retry_result

          assert retry_state.rto_ms == rto_ms
          assert retry_state.unacked_segments == current_state.unacked_segments
          assert retry_state.link_retry_path == :retransmit
          assert retry_state.link_retry_ms == min(current_state.link_retry_ms * 2, 1_000)

          deadline = deadline || retry_state.link_stall_deadline_ms
          assert retry_state.link_stall_deadline_ms == deadline
          {retry_state, deadline}
        end)

      assert DummyLink.get_packets(link) == []
      assert is_integer(deadline)

      :ok = DummyLink.set_send_result(link, :ok)

      assert {:keep_state, retransmitted_state, {{:timeout, :rto}, retransmit_rto, :retransmit}} =
               Tricep.Socket.retry_link_retransmit(stalled_state)

      assert retransmit_rto == stalled_state.rto_ms * 2
      assert [{seq, seq_end, "payload", 1}] = retransmitted_state.unacked_segments
      assert retransmitted_state.link_stall_deadline_ms == nil
      assert retransmitted_state.link_retry_path == nil
      assert retransmitted_state.link_retry_ms == 10
      assert_receive {:dummy_link_packet, ^link, _retransmitted_packet}, 1000

      :sys.replace_state(socket, fn {:established, _state} ->
        {:established, retransmitted_state}
      end)

      {{_, source_port}, _} = retransmitted_state.pair

      ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, source_port}},
          retransmitted_state.tcb.irs + 1,
          seq_end,
          [:ack],
          32_768
        )

      DummyLink.inject_packet(link, ack)

      assert {:established, %{unacked_segments: [], rto_timer_active: false}} =
               wait_for_socket(socket, fn
                 {:established, %{unacked_segments: []}} -> true
                 _ -> false
               end)

      assert seq == state.tcb.snd_una
    end

    test "preserves SYN, SYN-ACK, and FIN retry state while link admission fails", %{
      link: link,
      local_addr: _local_addr,
      remote_addr: _remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      connect_task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      assert_receive {:dummy_link_packet, ^link, _syn_packet}, 1_000
      assert {{:syn_sent, _from}, state} = :sys.get_state(socket)

      :ok = DummyLink.clear_packets(link)
      :ok = DummyLink.set_send_result(link, {:error, :eagain})
      rto_ms = state.rto_ms
      retry_ms = state.link_retry_ms

      assert {:keep_state, syn_state,
              {{:timeout, :link_retry}, ^retry_ms, {:retry, {:syn, :syn_timeout_nowait}}}} =
               Tricep.Socket.retransmit_syn(state, :syn_timeout_nowait)

      assert syn_state.syn_retransmit_count == state.syn_retransmit_count
      assert syn_state.rto_ms == rto_ms
      assert is_integer(syn_state.link_stall_deadline_ms)
      assert syn_state.link_retry_path == {:syn, :syn_timeout_nowait}
      assert syn_state.link_retry_ms == 20

      syn_ack_input = %{state | tcb: %{state.tcb | rcv_mss: 1460, rcv_nxt: 0}}

      assert {:keep_state, syn_ack_state,
              {{:timeout, :link_retry}, ^retry_ms, {:retry, :syn_ack}}} =
               Tricep.Socket.retransmit_syn_ack(syn_ack_input)

      assert syn_ack_state.syn_retransmit_count == state.syn_retransmit_count
      assert syn_ack_state.rto_ms == rto_ms
      assert is_integer(syn_ack_state.link_stall_deadline_ms)
      assert syn_ack_state.link_retry_path == :syn_ack
      assert syn_ack_state.link_retry_ms == 20

      fin_tcb = %{state.tcb | rcv_nxt: 0, rcv_adv_wnd: 65_535}

      fin_state = %{
        state
        | tcb: fin_tcb,
          unacked_segments: [{fin_tcb.snd_nxt, fin_tcb.snd_nxt + 1, :fin, 0}],
          rto_timer_active: true
      }

      assert {:keep_state, retained_fin_state,
              {{:timeout, :link_retry}, ^retry_ms, {:retry, :retransmit}}} =
               Tricep.Socket.do_retransmit(fin_state)

      assert retained_fin_state.unacked_segments == fin_state.unacked_segments
      assert retained_fin_state.rto_ms == rto_ms
      assert is_integer(retained_fin_state.link_stall_deadline_ms)
      assert retained_fin_state.link_retry_path == :retransmit
      assert retained_fin_state.link_retry_ms == 20
      assert DummyLink.get_packets(link) == []

      expired_deadline = System.monotonic_time(:millisecond) - 1

      exhausted_state = %{
        state
        | link_stall_deadline_ms: expired_deadline,
          link_retry_path: {:syn, :syn_timeout_nowait},
          link_retry_ms: 1_000
      }

      assert {:link_stall_exhausted, _syn_exhausted_state, :enobufs} =
               Tricep.Socket.retry_link_syn(exhausted_state, :syn_timeout_nowait)

      exhausted_syn_ack_state = %{
        syn_ack_input
        | link_stall_deadline_ms: expired_deadline,
          link_retry_path: :syn_ack,
          link_retry_ms: 1_000
      }

      assert {:link_stall_exhausted, _syn_ack_exhausted_state, :enobufs} =
               Tricep.Socket.retry_link_syn_ack(exhausted_syn_ack_state)

      exhausted_fin_state = %{
        fin_state
        | link_stall_deadline_ms: expired_deadline,
          link_retry_path: :retransmit,
          link_retry_ms: 1_000
      }

      assert {:next_state, :closed, _closed_data, _actions} =
               Tricep.Socket.retry_link_retransmit(exhausted_fin_state)

      :ok = DummyLink.set_send_result(link, {:error, :emsgsize})

      assert {:link_stall_exhausted, _syn_oversized_state, :emsgsize} =
               Tricep.Socket.retransmit_syn(state, :syn_timeout_nowait)

      assert {:link_stall_exhausted, _syn_ack_oversized_state, :emsgsize} =
               Tricep.Socket.retransmit_syn_ack(syn_ack_input)

      assert {:next_state, :closed, _closed_data, _actions} =
               Tricep.Socket.do_retransmit(fin_state)

      Task.shutdown(connect_task, :brutal_kill)
      stop_socket(socket)
    end

    test "bounds data-link stalls and rejects a permanently oversized packet", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1_000
      assert {:established, state} = :sys.get_state(socket)

      :ok = DummyLink.set_send_result(link, {:error, :eagain})

      {stalled_state, deadline} =
        Enum.reduce(
          1..6,
          {%{state | send_buffer: Tricep.DataBuffer.append(state.send_buffer, "x")}, nil},
          fn
            attempt, {current_state, deadline} ->
              expected_delay = (10 * 2 ** (attempt - 1)) |> min(1_000)

              retry_result =
                if current_state.link_retry_path do
                  Tricep.Socket.retry_link_send(current_state)
                else
                  Tricep.Socket.do_flush_send_buffer(current_state)
                end

              assert {:keep_state, next_state,
                      {{:timeout, :link_retry}, ^expected_delay, {:retry, :flush}}} = retry_result

              deadline = deadline || next_state.link_stall_deadline_ms
              assert next_state.link_stall_deadline_ms == deadline
              assert next_state.link_retry_path == :flush
              {next_state, deadline}
          end
        )

      assert is_integer(deadline)

      expired_state = %{
        stalled_state
        | link_stall_deadline_ms: System.monotonic_time(:millisecond) - 1
      }

      assert {:next_state, :closed, _closed_data, terminal_actions} =
               Tricep.Socket.retry_link_send(expired_state)

      refute Enum.any?(terminal_actions, fn
               {{:timeout, :link_retry}, _, {:retry, :flush}} -> true
               _action -> false
             end)

      :ok = DummyLink.set_send_result(link, {:error, :emsgsize})

      oversized_state = %{state | send_buffer: Tricep.DataBuffer.append(state.send_buffer, "x")}

      assert {:next_state, :closed, _closed_data, oversized_actions} =
               Tricep.Socket.do_flush_send_buffer(oversized_state)

      refute Enum.any?(oversized_actions, fn
               {{:timeout, :link_retry}, _, {:retry, :flush}} -> true
               _action -> false
             end)

      stop_socket(socket)
    end

    test "starts a fresh link-stall episode after an unsendable retry", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)

      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1_000
      assert {:established, state} = :sys.get_state(socket)
      :ok = DummyLink.set_send_result(link, {:error, :eagain})

      pending_state = %{
        state
        | send_buffer: Tricep.DataBuffer.append(state.send_buffer, "pending")
      }

      assert {:keep_state, stalled_state, {{:timeout, :link_retry}, 10, {:retry, :flush}}} =
               Tricep.Socket.do_flush_send_buffer(pending_state)

      original_deadline = System.monotonic_time(:millisecond) + 500
      stalled_state = %{stalled_state | link_stall_deadline_ms: original_deadline}
      attempts = DummyLink.send_attempts(link)
      window_closed_state = %{stalled_state | tcb: %{stalled_state.tcb | snd_wnd: 0}}

      assert {:keep_state, paused_state, paused_actions} =
               Tricep.Socket.retry_link_send(window_closed_state)

      assert paused_state.link_stall_deadline_ms == nil
      assert paused_state.link_retry_path == nil
      assert paused_state.link_retry_ms == 10

      refute Enum.any?(List.wrap(paused_actions), fn
               {{:timeout, :link_retry}, _, {:retry, :flush}} -> true
               _action -> false
             end)

      assert DummyLink.send_attempts(link) == attempts

      reopened_state = %{paused_state | tcb: %{paused_state.tcb | snd_wnd: 32_768}}

      assert {:keep_state, fresh_state, {{:timeout, :link_retry}, 10, {:retry, :flush}}} =
               Tricep.Socket.do_flush_send_buffer(reopened_state)

      assert fresh_state.link_stall_deadline_ms > original_deadline
      assert fresh_state.link_retry_path == :flush
    end

    test "rearms the named RTO when a deferred flush retry finds a full window", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)

      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1_000
      assert {:established, state} = :sys.get_state(socket)
      attempts = DummyLink.send_attempts(link)

      payload = "flight"
      payload_size = byte_size(payload)
      seq_start = state.tcb.snd_una
      seq_end = seq_start + payload_size

      full_window_state = %{
        state
        | tcb: %{
            state.tcb
            | snd_nxt: seq_end,
              snd_wnd: payload_size
          },
          unacked_segments: [{seq_start, seq_end, payload, 0}],
          send_buffer: Tricep.DataBuffer.append(state.send_buffer, "queued"),
          rto_timer_active: true,
          link_stall_deadline_ms: System.monotonic_time(:millisecond) + 5_000,
          link_retry_path: :flush,
          link_retry_ms: 20
      }

      # The actual named RTO event is deferred while the named flush retry
      # owns link admission. Its timer has fired, so the retry's unsendable
      # exit must install a new named RTO for the in-flight payload.
      assert {:keep_state, deferred_rto_state} = Tricep.Socket.do_retransmit(full_window_state)
      refute deferred_rto_state.rto_timer_active
      assert deferred_rto_state.link_retry_path == :flush
      assert deferred_rto_state.tcb.snd_wnd > 0
      assert deferred_rto_state.tcb.snd_nxt != deferred_rto_state.tcb.snd_una

      assert {:keep_state, recovered_state, [{{:timeout, :rto}, rto_ms, :retransmit}]} =
               Tricep.Socket.retry_link_send(deferred_rto_state)

      assert rto_ms == state.rto_ms
      assert recovered_state.rto_timer_active
      assert recovered_state.unacked_segments == full_window_state.unacked_segments
      assert recovered_state.link_stall_deadline_ms == nil
      assert recovered_state.link_retry_path == nil
      assert recovered_state.link_retry_ms == 10
      assert recovered_state.tcb.snd_wnd > 0
      assert recovered_state.tcb.snd_nxt != recovered_state.tcb.snd_una
      assert DummyLink.send_attempts(link) == attempts
    end

    test "coalesces rapid writes and ACK bursts behind an armed link retry", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1_000
      assert {:established, state} = :sys.get_state(socket)

      :ok = DummyLink.set_send_result(link, {:error, :eagain})

      pending_state = %{
        state
        | send_buffer: Tricep.DataBuffer.append(state.send_buffer, "first")
      }

      assert {:keep_state, retry_state, {{:timeout, :link_retry}, 10, {:retry, :flush}}} =
               Tricep.Socket.do_flush_send_buffer(pending_state)

      deadline = retry_state.link_stall_deadline_ms
      attempts = DummyLink.send_attempts(link)

      write_state =
        Enum.reduce(1..12, retry_state, fn number, current_state ->
          assert {:keep_state, next_state, _actions} =
                   Tricep.Socket.handle_send_call(
                     current_state,
                     {self(), make_ref()},
                     "write-#{number}",
                     :infinity
                   )

          assert :keep_state_and_data = Tricep.Socket.do_flush_send_buffer(next_state)
          assert next_state.link_stall_deadline_ms == deadline
          assert next_state.link_retry_path == :flush
          next_state
        end)

      ack = %{
        flags: [:ack],
        seq: write_state.tcb.irs + 1,
        ack: write_state.tcb.snd_una,
        window: 65_535,
        payload: <<>>
      }

      Enum.each(1..12, fn _ ->
        assert {:keep_state, ack_state, _actions} =
                 Tricep.Socket.handle_established_segment(write_state, ack)

        assert :keep_state_and_data = Tricep.Socket.do_flush_send_buffer(ack_state)
        assert ack_state.link_stall_deadline_ms == deadline
        assert ack_state.link_retry_path == :flush
      end)

      assert DummyLink.send_attempts(link) == attempts
      assert deadline > System.monotonic_time(:millisecond)
      stop_socket(socket)
    end

    test "shares one stall deadline across retransmit and flush paths", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1_000
      assert Tricep.send(socket, "payload") == :ok
      assert_receive {:dummy_link_packet, ^link, _payload}, 1_000
      assert {:established, state} = :sys.get_state(socket)

      :ok = DummyLink.set_send_result(link, {:error, :eagain})

      assert {:keep_state, retry_state, {{:timeout, :link_retry}, _delay, {:retry, :retransmit}}} =
               Tricep.Socket.do_retransmit(state)

      deadline = retry_state.link_stall_deadline_ms

      retry_state = %{
        retry_state
        | send_buffer: Tricep.DataBuffer.append(retry_state.send_buffer, "queued")
      }

      attempts = DummyLink.send_attempts(link)

      assert :keep_state_and_data = Tricep.Socket.do_flush_send_buffer(retry_state)
      assert {:keep_state, deferred_rto_state} = Tricep.Socket.do_retransmit(retry_state)
      assert deferred_rto_state.link_stall_deadline_ms == deadline
      assert deferred_rto_state.link_retry_path == :retransmit
      assert DummyLink.send_attempts(link) == attempts
      stop_socket(socket)
    end

    test "closes only when an armed link retry reaches its elapsed deadline", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      Process.unlink(socket)

      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1_000
      :ok = DummyLink.clear_packets(link)
      :ok = DummyLink.set_send_result(link, {:error, :eagain})
      assert Tricep.send(socket, "pending") == :ok

      {:established, stalled_state} =
        wait_for_socket(socket, fn
          {:established, %{link_retry_path: :flush}} -> true
          _ -> false
        end)

      short_deadline = System.monotonic_time(:millisecond) + 75

      assert {:established, %{link_stall_deadline_ms: ^short_deadline}} =
               :sys.replace_state(socket, fn {:established, state} ->
                 {:established,
                  %{state | link_stall_deadline_ms: short_deadline, link_retry_ms: 10}}
               end)

      assert stalled_state.link_stall_deadline_ms > System.monotonic_time(:millisecond)
      assert {:closed, %{socket_opts: %{}}} = wait_for_state_name(socket, :closed, 1_000)
      assert DummyLink.get_packets(link) == []

      Process.sleep(100)
      assert Process.alive?(socket)
      assert {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)
    end

    test "rejects writes larger than the configured high watermark", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket =
        establish_connection(link, local_addr, remote_addr, open_opts: %{send_buffer_size: 4})

      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000
      assert Tricep.send(socket, "abcde") == {:error, :emsgsize}
      refute_receive {:dummy_link_packet, ^link, _packet}, 100

      assert {:established, state} = :sys.get_state(socket)
      assert Tricep.DataBuffer.empty?(state.send_buffer)
      assert state.unacked_segments == []
    end

    test "releases a dead blocking sender and its retained bytes", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket =
        establish_connection(link, local_addr, remote_addr,
          window: 0,
          open_opts: %{send_buffer_size: 4, send_waiter_limit: 2}
        )

      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000
      task = Task.async(fn -> Tricep.send(socket, "abcd", :infinity) end)
      wait_for_send_waiters(socket)

      assert {:established, %{send_waiters: [{:wait, _from, "abcd", nil, _monitor}]}} =
               :sys.get_state(socket)

      Task.shutdown(task, :brutal_kill)

      wait_for_socket(socket, fn
        {:established, %{send_waiters: []}} -> true
        _ -> false
      end)

      assert Tricep.send(socket, "abcd", 0) == {:error, :timeout}
    end

    test "link termination resets the socket and settles blocked sends", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 0)

      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000
      task = Task.async(fn -> Tricep.send(socket, "blocked", :infinity) end)
      wait_for_send_waiters(socket)

      Process.unlink(link)
      GenServer.stop(link, :shutdown)

      assert Task.await(task, 1_000) == {:error, :enetdown}
      assert {:closed, %{socket_opts: %{}}} = wait_for_state_name(socket, :closed, 1_000)
    end

    test "link termination settles a pending blocking connect", %{
      link: link,
      local_addr: _local_addr,
      remote_addr: _remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      assert_receive {:dummy_link_packet, ^link, _syn}, 1_000
      Process.unlink(link)
      GenServer.stop(link, :shutdown)

      assert Task.await(task, 1_000) == {:error, :enetdown}
      assert {:closed, %{socket_opts: %{}}} = wait_for_state_name(socket, :closed, 1_000)
    end

    test "link termination cancels the FIN_WAIT_2 timer", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket =
        establish_connection(link, local_addr, remote_addr,
          open_opts: %{fin_wait_2_timeout_ms: 25}
        )

      on_exit(fn -> stop_socket(socket) end)
      Process.unlink(socket)

      shutdown_write_to_fin_wait_2(socket, link, local_addr, remote_addr)
      assert {:fin_wait_2, _state} = :sys.get_state(socket)

      Process.unlink(link)
      GenServer.stop(link, :shutdown)

      assert {:closed, %{socket_opts: %{fin_wait_2_timeout_ms: 25}}} =
               wait_for_state_name(socket, :closed, 1_000)

      Process.sleep(75)
      assert Process.alive?(socket)
      assert {:closed, %{socket_opts: %{fin_wait_2_timeout_ms: 25}}} = :sys.get_state(socket)
    end

    test "link termination cancels the TIME_WAIT timer", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      Process.unlink(socket)

      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1_000

      {_established_state, _time_wait_state} =
        enter_time_wait(socket, link, local_addr, remote_addr)

      Process.unlink(link)
      GenServer.stop(link, :shutdown)

      assert {:closed, %{socket_opts: %{}}} = wait_for_state_name(socket, :closed, 1_000)

      # The socket would have crashed after this state-owned timer fired if
      # link-down teardown had left it armed during the callback transition.
      Process.sleep(2_100)
      assert Process.alive?(socket)
      assert {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)
    end

    test "rejects invalid send-capacity options at open time" do
      assert {:error, :einval} =
               Tricep.open(:inet6, :stream, :tcp, %{send_buffer_size: 0})

      assert {:error, :einval} =
               Tricep.open(:inet6, :stream, :tcp, %{
                 send_buffer_size: 8,
                 send_buffer_low_watermark: 8
               })
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
      assert ack_parsed.ack == state.tcb.irs + 1 + byte_size("Hello from peer")
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "abcdef"
        )

      DummyLink.inject_packet(link, data_segment)

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_::binary-size(40), ack_segment::binary>> = ack_packet
      ack_parsed = Tcp.parse_segment(ack_segment)

      assert ack_parsed.ack == state.tcb.irs + 1 + byte_size("abcdef")
      assert ack_parsed.window == 4

      {:established, buffered_state} = :sys.get_state(socket)
      assert buffered_state.tcb.rcv_wnd == 4
      assert buffered_state.recv_buffer == "abcdef"

      assert Tricep.recv(socket, 3, 1000) == {:ok, "abc"}

      assert_receive {:dummy_link_packet, _link, update_packet}, 1000
      <<_::binary-size(40), update_segment::binary>> = update_packet
      update_parsed = Tcp.parse_segment(update_segment)

      assert update_parsed.ack == ack_parsed.ack
      assert update_parsed.window == 7

      {:established, reopened_state} = :sys.get_state(socket)
      assert reopened_state.tcb.rcv_wnd == 7
      assert reopened_state.recv_buffer == "def"
    end

    test "recv does not repeat a capped unscaled window advertisement", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket =
        establish_connection(link, local_addr, remote_addr,
          open_opts: %{recv_buffer_size: 1_000_000}
        )

      assert_receive {:dummy_link_packet, _link, _handshake_ack}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair
      assert state.tcb.rcv_wnd == 65_535
      refute state.tcb.window_scaling_negotiated

      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: "ab"
        )

      DummyLink.inject_packet(link, data_segment)

      assert_receive {:dummy_link_packet, _link, data_ack_packet}, 1000
      <<_ip_header::binary-size(40), data_ack_segment::binary>> = data_ack_packet
      assert Tcp.parse_segment(data_ack_segment).window == 65_535

      assert Tricep.recv(socket, 1, 1000) == {:ok, "a"}
      refute_receive {:dummy_link_packet, _link, _window_update}, 100

      assert Tricep.recv(socket, 1, 1000) == {:ok, "b"}
      refute_receive {:dummy_link_packet, _link, _window_update}, 100

      assert {:established, %{tcb: %{rcv_wnd: 65_535}, recv_buffer: <<>>}} =
               :sys.get_state(socket)
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "123456789"
        )

      DummyLink.inject_packet(link, data_segment)

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_::binary-size(40), ack_segment::binary>> = ack_packet
      ack_parsed = Tcp.parse_segment(ack_segment)

      assert ack_parsed.ack == state.tcb.irs + 1 + 5
      assert ack_parsed.window == 0

      {:established, buffered_state} = :sys.get_state(socket)
      assert buffered_state.recv_buffer == "12345"
      assert buffered_state.tcb.rcv_nxt == state.tcb.irs + 1 + 5
      assert buffered_state.tcb.rcv_wnd == 0
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 1 + 10,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
    test "RST cancels an armed RTO and leaves the closed socket alive", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      Process.unlink(socket)

      assert_receive {:dummy_link_packet, ^link, _handshake_ack_packet}, 1000

      assert {:established, %{rto_ms: 100}} =
               :sys.replace_state(socket, fn
                 {:established, state} -> {:established, %{state | rto_ms: 100}}
               end)

      assert Tricep.send(socket, "unacknowledged") == :ok
      assert_receive {:dummy_link_packet, ^link, _data_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      assert state.rto_timer_active
      {{_, src_port}, _} = state.pair

      rst =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst)
      assert {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)

      # The old 100 ms RTO deadline must not terminate this socket process.
      Process.sleep(200)
      assert Process.alive?(socket)
      assert {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)
    end

    test "reconnects after RTO teardown without stale retransmission", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      Process.unlink(socket)

      assert_receive {:dummy_link_packet, ^link, _handshake_ack_packet}, 1000

      assert {:established, %{rto_ms: 100}} =
               :sys.replace_state(socket, fn
                 {:established, state} -> {:established, %{state | rto_ms: 100}}
               end)

      assert Tricep.send(socket, "old data") == :ok
      assert_receive {:dummy_link_packet, ^link, _old_data_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      rst =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst)
      assert {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)

      # Prove the old RTO deadline is past before a new connection can arm a
      # replacement timer.
      Process.sleep(200)
      assert Process.alive?(socket)
      assert {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)

      reconnect_socket(socket, link, local_addr, remote_addr, 6_000)
      assert {:established, reconnected_state} = :sys.get_state(socket)
      assert reconnected_state.unacked_segments == []

      assert Tricep.send(socket, "fresh data") == :ok
      assert_receive {:dummy_link_packet, ^link, fresh_data_packet}, 1000
      <<_::binary-size(40), fresh_data_segment::binary>> = fresh_data_packet
      fresh_data = Tcp.parse_segment(fresh_data_segment)
      assert fresh_data.payload == "fresh data"

      {{_, reconnected_port}, _} = reconnected_state.pair

      fresh_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, reconnected_port}},
          reconnected_state.tcb.rcv_nxt,
          wrap_seq(fresh_data.seq + byte_size(fresh_data.payload)),
          [:ack],
          32_768
        )

      DummyLink.inject_packet(link, fresh_ack)

      wait_for_socket(socket, fn
        {:established, %{unacked_segments: [], rto_timer_active: false}} -> true
        _state -> false
      end)

      # The former 100 ms RTO cannot retransmit the previous incarnation.
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 200
      assert Process.alive?(socket)
      assert {:established, %{unacked_segments: []}} = :sys.get_state(socket)
    end

    test "RST in CLOSE_WAIT cancels an armed RTO", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      Process.unlink(socket)

      assert_receive {:dummy_link_packet, ^link, _handshake_ack_packet}, 1000
      assert {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      peer_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:fin, :ack],
          32_768
        )

      DummyLink.inject_packet(link, peer_fin)
      assert_receive {:dummy_link_packet, ^link, _peer_fin_ack}, 1000
      assert {:close_wait, _close_wait_state} = :sys.get_state(socket)

      assert {:close_wait, %{rto_ms: 100}} =
               :sys.replace_state(socket, fn
                 {:close_wait, current_state} -> {:close_wait, %{current_state | rto_ms: 100}}
               end)

      assert Tricep.send(socket, "unacknowledged") == :ok
      assert_receive {:dummy_link_packet, ^link, _data_packet}, 1000
      assert {:close_wait, armed_state} = :sys.get_state(socket)
      assert armed_state.rto_timer_active

      rst =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          armed_state.tcb.rcv_nxt,
          armed_state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst)
      assert {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)

      Process.sleep(200)
      assert Process.alive?(socket)
    end

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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      # Recv should return error
      assert Task.await(recv_task, 1000) == {:error, :econnreset}
    end

    test "exact RST preserves default options for bind and reconnect", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)

      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000
      assert {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      exact_rst =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, exact_rst)

      assert {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)
      assert Process.alive?(socket)

      assert Tricep.bind(socket, %{family: :inet6, addr: remote_addr, port: 0}) == :ok

      assert {:bound, %{socket_opts: %{}, local_addr: ^remote_addr, local_port: local_port}} =
               :sys.get_state(socket)

      assert local_port in 49_152..65_535
      assert Tricep.close(socket) == :ok
      assert {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)

      reconnect_socket(socket, link, local_addr, remote_addr, 6_000)
      assert {:established, %{socket_opts: %{}}} = :sys.get_state(socket)
    end

    test "in-window non-exact RST is rejected with a challenge ACK", %{
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
          wrap_seq(state.tcb.rcv_nxt + 1),
          state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      assert_challenge_ack(link, state)
      {:established, _state} = :sys.get_state(socket)
    end

    test "RST outside the receive window is silently dropped", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket =
        establish_connection(link, local_addr, remote_addr,
          open_opts: %{recv_buffer_size: 1_000_000}
        )

      # Drain the ACK packet
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair
      assert state.tcb.rcv_wnd == 65_535

      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.tcb.rcv_nxt + 65_535),
          state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      refute_receive {:dummy_link_packet, _link, _packet}, 100
      {:established, _state} = :sys.get_state(socket)
    end

    test "old RST is silently dropped", %{
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
          wrap_seq(state.tcb.rcv_nxt - 1),
          state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      refute_receive {:dummy_link_packet, _link, _packet}, 100
      assert {:established, _state} = :sys.get_state(socket)
    end

    test "unexpected SYN is challenge-ACKed irrespective of its sequence number", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      syn_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.tcb.rcv_nxt + state.tcb.rcv_wnd),
          0,
          [:syn],
          0
        )

      DummyLink.inject_packet(link, syn_segment)

      assert_challenge_ack(link, state)
      assert {:established, _state} = :sys.get_state(socket)
    end

    test "limits RFC 5961 challenge ACKs per socket", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket =
        establish_connection(link, local_addr, remote_addr,
          open_opts: %{challenge_ack_limit: 2, challenge_ack_interval_ms: 60_000}
        )

      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.tcb.rcv_nxt + 1),
          state.tcb.snd_nxt,
          [:rst],
          0
        )

      Enum.each(1..3, fn _ -> DummyLink.inject_packet(link, rst_segment) end)

      assert_challenge_ack(link, state)
      assert_challenge_ack(link, state)
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      assert {:established, %{challenge_ack_limiter: %{sent: 2}}} = :sys.get_state(socket)
    end

    test "shares and renews one RFC 5961 challenge ACK quota for RST and SYN", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket =
        establish_connection(link, local_addr, remote_addr,
          open_opts: %{challenge_ack_limit: 2, challenge_ack_interval_ms: 60_000}
        )

      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000
      assert {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      rst =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.tcb.rcv_nxt + 1),
          state.tcb.snd_nxt,
          [:rst],
          0
        )

      syn =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.tcb.rcv_nxt + state.tcb.rcv_wnd),
          0,
          [:syn],
          0
        )

      DummyLink.inject_packet(link, rst)
      DummyLink.inject_packet(link, syn)

      assert_challenge_ack(link, state)
      assert_challenge_ack(link, state)

      DummyLink.inject_packet(link, rst)
      refute_receive {:dummy_link_packet, ^link, _}, 100

      :sys.replace_state(socket, fn {:established, established_state} ->
        limiter = %{
          established_state.challenge_ack_limiter
          | sent: established_state.challenge_ack_limiter.limit,
            window_started_at:
              System.monotonic_time(:millisecond) -
                established_state.challenge_ack_limiter.interval_ms
        }

        {:established, %{established_state | challenge_ack_limiter: limiter}}
      end)

      assert {:established, renewed_state} = :sys.get_state(socket)

      DummyLink.inject_packet(link, syn)
      DummyLink.inject_packet(link, rst)

      assert_challenge_ack(link, renewed_state)
      assert_challenge_ack(link, renewed_state)

      DummyLink.inject_packet(link, syn)
      refute_receive {:dummy_link_packet, ^link, _}, 100
      assert {:established, %{challenge_ack_limiter: %{sent: 2}}} = :sys.get_state(socket)
    end

    test "retains supplied socket configuration across reset, timeout, and reconnect", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket_opts = %{
        recv_buffer_size: 100_000,
        fin_wait_2_timeout_ms: 25,
        challenge_ack_limit: 1,
        challenge_ack_interval_ms: 60_000
      }

      socket =
        establish_connection(link, local_addr, remote_addr, open_opts: socket_opts)

      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      assert {:established, first_state} = :sys.get_state(socket)
      assert first_state.socket_opts == socket_opts
      assert first_state.recv_buffer_size == 100_000
      assert first_state.fin_wait_2_timeout_ms == 25
      assert first_state.challenge_ack_limiter.limit == 1
      assert first_state.challenge_ack_limiter.interval_ms == 60_000
      {{_, first_port}, _} = first_state.pair

      challenge_rst =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, first_port}},
          wrap_seq(first_state.tcb.rcv_nxt + 1),
          first_state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, challenge_rst)
      assert_challenge_ack(link, first_state)

      exact_rst =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, first_port}},
          first_state.tcb.rcv_nxt,
          first_state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, exact_rst)
      assert {:closed, %{socket_opts: ^socket_opts}} = :sys.get_state(socket)

      reconnect_socket(socket, link, local_addr, remote_addr, 6_000)
      assert {:established, reconnected_state} = :sys.get_state(socket)

      assert reconnected_state.socket_opts == socket_opts
      assert reconnected_state.recv_buffer_size == 100_000
      assert reconnected_state.fin_wait_2_timeout_ms == 25
      assert reconnected_state.challenge_ack_limiter.limit == 1
      assert reconnected_state.challenge_ack_limiter.interval_ms == 60_000
      assert reconnected_state.challenge_ack_limiter.sent == 0
      {{_, reconnected_port}, _} = reconnected_state.pair

      fresh_challenge_rst =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, reconnected_port}},
          wrap_seq(reconnected_state.tcb.rcv_nxt + 1),
          reconnected_state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, fresh_challenge_rst)
      assert_challenge_ack(link, reconnected_state)

      exhausted_syn =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, reconnected_port}},
          wrap_seq(reconnected_state.tcb.rcv_nxt + reconnected_state.tcb.rcv_wnd),
          0,
          [:syn],
          0
        )

      DummyLink.inject_packet(link, exhausted_syn)
      refute_receive {:dummy_link_packet, ^link, _}, 100

      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, ^link, _fin_packet}, 1000

      fin_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, reconnected_port}},
          reconnected_state.tcb.rcv_nxt,
          wrap_seq(reconnected_state.tcb.snd_nxt + 1),
          [:ack],
          32_768
        )

      DummyLink.inject_packet(link, fin_ack)
      assert {:fin_wait_2, _} = :sys.get_state(socket)

      wait_for_state_name(socket, :closed, 1_000)
      assert {:closed, %{socket_opts: ^socket_opts}} = :sys.get_state(socket)

      reconnect_socket(socket, link, local_addr, remote_addr, 7_000)
      assert {:established, final_state} = :sys.get_state(socket)
      assert final_state.socket_opts == socket_opts
      assert final_state.recv_buffer_size == 100_000
      assert final_state.fin_wait_2_timeout_ms == 25
      assert final_state.challenge_ack_limiter.limit == 1
      assert final_state.challenge_ack_limiter.interval_ms == 60_000
      assert final_state.challenge_ack_limiter.sent == 0
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

      assert {:established, %{persist_timer_active: true}} = :sys.get_state(socket)

      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      assert Task.await(send_task, 1000) == {:error, :econnreset}
      {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)

      # The first persist timer is one second. It must not kill the closed
      # socket (or its linked owner) if cancellation raced with the reset.
      Process.sleep(1_100)
      assert Process.alive?(socket)
      assert Process.alive?(self())
    end

    test "stray persist probes are absorbed by root and closing callbacks" do
      assert :keep_state_and_data =
               Tricep.Socket.handle_event(
                 {:timeout, :persist},
                 :persist_probe,
                 :closed,
                 %{socket_opts: %{}}
               )

      state = %Tricep.Socket{
        link: self(),
        pair: {{<<0::128>>, 0}, {<<1::128>>, 1}},
        persist_timer_active: true
      }

      assert {:next_state, :closed, %{socket_opts: %{}}, actions} =
               Tricep.Socket.synchronized_rejection(state, :acceptable_reset, :close)

      assert {{:timeout, :persist}, :cancel} in actions

      for state_name <- [:fin_wait_2, :closing, :last_ack, :time_wait] do
        assert :keep_state_and_data =
                 Closing.handle_event(
                   {:timeout, :persist},
                   :persist_probe,
                   state_name,
                   state
                 )
      end
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      assert Task.await(send_task, 1000) == {:error, :econnreset}
      {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)

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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
      initial_snd_wnd = state.tcb.snd_wnd

      # Inject a pure ACK with different window
      new_window = 65535

      ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
          [:ack],
          new_window
        )

      DummyLink.inject_packet(link, ack_segment)

      # Check window was updated
      {:established, new_state} = :sys.get_state(socket)
      assert new_state.tcb.snd_wnd == new_window
      assert new_state.tcb.snd_wnd != initial_snd_wnd or initial_snd_wnd == new_window
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
          wrap_seq(state_before_ack.tcb.rcv_nxt - 1),
          state_before_ack.tcb.snd_nxt,
          [:ack],
          65_535
        )

      DummyLink.inject_packet(link, off_window_ack)

      assert_receive {:dummy_link_packet, _link, challenge_packet}, 1000
      <<_ip_header::binary-size(40), challenge_segment::binary>> = challenge_packet
      challenge = Tcp.parse_segment(challenge_segment)

      assert :ack in challenge.flags
      assert challenge.seq == state_before_ack.tcb.snd_nxt
      assert challenge.ack == state_before_ack.tcb.rcv_nxt

      {:established, state_after_ack} = :sys.get_state(socket)

      assert state_after_ack.tcb.snd_una == state_before_ack.tcb.snd_una
      assert state_after_ack.tcb.snd_wnd == state_before_ack.tcb.snd_wnd
      assert state_after_ack.unacked_segments == state_before_ack.unacked_segments
      assert state_after_ack.rto_timer_active == state_before_ack.rto_timer_active
    end

    test "ACK-less in-order data is acknowledged without waking receivers", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack_packet}, 1000

      assert {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      recv_task = Task.async(fn -> Tricep.recv(socket, 0, 5_000) end)
      wait_for_recv_waiters(socket)
      assert {:select, {:select_info, :recv, ref}} = Tricep.recv(socket, 0, :nowait)

      assert {:established, before_state} = :sys.get_state(socket)
      assert length(before_state.recv_waiters) == 1
      assert length(before_state.recv_selects) == 1

      ackless_data =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:psh],
          0,
          payload: "must not deliver"
        )

      DummyLink.inject_packet(link, ackless_data)
      assert_receive {:dummy_link_packet, ^link, ack_packet}, 1000
      <<_::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert ack.flags == [:ack]
      assert ack.payload == <<>>
      assert ack.seq == before_state.tcb.snd_nxt
      assert ack.ack == before_state.tcb.rcv_nxt
      assert ack.window == before_state.tcb.rcv_adv_wnd
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100
      refute_receive {:"$socket", ^socket, :select, ^ref}, 100
      assert Task.yield(recv_task, 50) == nil

      assert {:established, after_state} = :sys.get_state(socket)
      assert after_state.tcb.rcv_nxt == before_state.tcb.rcv_nxt
      assert after_state.recv_buffer == before_state.recv_buffer
      assert after_state.out_of_order_segments == before_state.out_of_order_segments
      assert after_state.out_of_order_fin == before_state.out_of_order_fin
      assert after_state.recv_waiters == before_state.recv_waiters
      assert after_state.recv_selects == before_state.recv_selects
      assert after_state.tcb.snd_wnd == 0
      assert after_state.tcb.snd_una == before_state.tcb.snd_una
      assert after_state.tcb.snd_nxt == before_state.tcb.snd_nxt
      refute after_state.persist_timer_active

      Task.shutdown(recv_task, :brutal_kill)
    end

    test "ACK-less left-overlapping data is acknowledged without waking receivers", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack_packet}, 1000

      assert {:established, state} = :sys.get_state(socket)

      assert_ackless_payloads_preserve_receive_state(
        socket,
        link,
        local_addr,
        remote_addr,
        :established,
        [
          {wrap_seq(state.tcb.rcv_nxt - 1), [:psh], "ab"},
          {wrap_seq(state.tcb.rcv_nxt - 2), [:psh, :fin], "abcd"}
        ]
      )
    end

    test "ACK-less left-overlapping data is rejected across sequence wrap", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, server_seq: 0xFFFFFFFD)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack_packet}, 1000

      assert {:established, %{tcb: %{rcv_nxt: 0xFFFFFFFE}} = state} = :sys.get_state(socket)

      assert_ackless_payloads_preserve_receive_state(
        socket,
        link,
        local_addr,
        remote_addr,
        :established,
        [
          {wrap_seq(state.tcb.rcv_nxt - 1), [:psh], "ab"},
          {wrap_seq(state.tcb.rcv_nxt - 2), [:psh, :fin], "abcd"}
        ]
      )
    end

    test "does not latch an ACK-less out-of-order bare or payload FIN", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack_packet}, 1000

      assert_ackless_out_of_order_fin_does_not_close(
        socket,
        link,
        local_addr,
        remote_addr,
        :established
      )
    end

    test "ACK-less future payload invalidates an advisory FIN", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack_packet}, 1000

      assert_ackless_future_payload_invalidates_advisory_fin(
        socket,
        link,
        local_addr,
        remote_addr,
        :established
      )
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
          state.tcb.rcv_nxt + 5,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "world"
        )

      DummyLink.inject_packet(link, out_of_order_segment)

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert :ack in ack.flags
      assert ack.ack == state.tcb.rcv_nxt

      assert Tricep.recv(socket, 0, 100) == {:error, :timeout}

      {:established, queued_state} = :sys.get_state(socket)
      assert queued_state.tcb.rcv_nxt == state.tcb.rcv_nxt
      assert [{seq, seq_end, payload}] = queued_state.out_of_order_segments
      assert seq == state.tcb.rcv_nxt + 5
      assert seq_end == state.tcb.rcv_nxt + 10
      assert payload == "world"

      gap_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "hello"
        )

      DummyLink.inject_packet(link, gap_segment)

      assert_receive {:dummy_link_packet, _link, final_ack_packet}, 1000
      <<_ip_header::binary-size(40), final_ack_segment::binary>> = final_ack_packet
      final_ack = Tcp.parse_segment(final_ack_segment)

      assert :ack in final_ack.flags
      assert final_ack.ack == state.tcb.rcv_nxt + 10

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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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

    test "trims a retransmitted prefix and delivers its new tail after a lost ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      first_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: "hello"
        )

      DummyLink.inject_packet(link, first_segment)
      assert_receive {:dummy_link_packet, ^link, first_ack_packet}, 1000
      <<_::binary-size(40), first_ack_segment::binary>> = first_ack_packet
      first_ack = Tcp.parse_segment(first_ack_segment)

      assert first_ack.flags == [:ack]
      assert first_ack.seq == state.tcb.snd_nxt
      assert first_ack.ack == wrap_seq(state.tcb.rcv_nxt + 5)
      assert first_ack.window == state.tcb.rcv_adv_wnd - 5
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      retransmission =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: "helloworld"
        )

      DummyLink.inject_packet(link, retransmission)
      assert_receive {:dummy_link_packet, ^link, ack_packet}, 1000
      <<_::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert ack.flags == [:ack]
      assert ack.seq == state.tcb.snd_nxt
      assert ack.ack == wrap_seq(state.tcb.rcv_nxt + 10)
      assert ack.window == state.tcb.rcv_adv_wnd - 10
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100
      assert Tricep.recv(socket, 0, 1000) == {:ok, "helloworld"}
    end

    test "processes a new ACK when an overlapping FIN retransmission commits", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      assert Tricep.send(socket, "outbound") == :ok
      assert_receive {:dummy_link_packet, ^link, outbound_packet}, 1000
      <<_::binary-size(40), outbound_segment::binary>> = outbound_packet
      outbound = Tcp.parse_segment(outbound_segment)

      assert {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair
      assert state.unacked_segments != []
      assert state.rto_timer_active

      first_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_una,
          [:ack, :psh],
          32_768,
          payload: "hello"
        )

      DummyLink.inject_packet(link, first_segment)
      assert_receive {:dummy_link_packet, ^link, first_ack_packet}, 1000
      <<_::binary-size(40), first_ack_segment::binary>> = first_ack_packet
      first_ack = Tcp.parse_segment(first_ack_segment)

      assert first_ack.flags == [:ack]
      assert first_ack.seq == state.tcb.snd_nxt
      assert first_ack.ack == wrap_seq(state.tcb.rcv_nxt + 5)
      assert first_ack.window == state.tcb.rcv_adv_wnd - 5
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      overlapping_fin_retransmission =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          wrap_seq(outbound.seq + byte_size(outbound.payload)),
          [:ack, :psh, :fin],
          32_768,
          payload: "helloworld"
        )

      DummyLink.inject_packet(link, overlapping_fin_retransmission)
      assert_receive {:dummy_link_packet, ^link, final_ack_packet}, 1000
      <<_::binary-size(40), final_ack_segment::binary>> = final_ack_packet
      final_ack = Tcp.parse_segment(final_ack_segment)

      assert final_ack.flags == [:ack]
      assert final_ack.seq == state.tcb.snd_nxt
      assert final_ack.ack == wrap_seq(state.tcb.rcv_nxt + 11)
      assert final_ack.window == state.tcb.rcv_adv_wnd - 10
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:close_wait, final_state} = :sys.get_state(socket)
      assert final_state.fin_received
      assert final_state.unacked_segments == []
      refute final_state.rto_timer_active
      assert Tricep.recv(socket, 0, 1000) == {:ok, "helloworld"}
      assert Tricep.recv(socket, 0, 1000) == {:ok, <<>>}
    end

    test "processes an in-order FIN-carried ACK through send bookkeeping", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {socket, state, close_wait_state} =
        close_wait_after_in_order_fin_carried_ack(link, local_addr, remote_addr)

      assert close_wait_state.fin_received
      assert close_wait_state.tcb.snd_una == state.tcb.snd_nxt
      assert close_wait_state.unacked_segments == []
      refute close_wait_state.rto_timer_active

      # CLOSE_WAIT remains write-capable after processing the peer's FIN.
      assert Tricep.send(socket, "still usable") == :ok
      assert_receive {:dummy_link_packet, ^link, usable_packet}, 1000
      <<_::binary-size(40), usable_segment::binary>> = usable_packet
      assert Tcp.parse_segment(usable_segment).payload == "still usable"
    end

    @tag :slow
    @tag :fin_ack_rto
    test "retransmits unacknowledged data without a FIN ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {_socket, _state, outbound} =
        established_with_unacknowledged_outbound(link, local_addr, remote_addr)

      # Positive control: the tagged check observes the normal 1s RTO.
      assert_receive {:dummy_link_packet, ^link, retransmission_packet}, 2500
      <<_::binary-size(40), retransmission_segment::binary>> = retransmission_packet
      retransmission = Tcp.parse_segment(retransmission_segment)

      assert retransmission.payload == outbound.payload
      assert retransmission.seq == outbound.seq
    end

    @tag :slow
    @tag :fin_ack_rto
    test "does not retransmit data acknowledged by an in-order FIN-carried ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {socket, _state, close_wait_state} =
        close_wait_after_in_order_fin_carried_ack(link, local_addr, remote_addr)

      assert close_wait_state.unacked_segments == []
      refute close_wait_state.rto_timer_active

      # A cancelled RTO must not retransmit the data that the FIN acknowledged.
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 2500
      assert Process.alive?(socket)
    end

    test "keeps known bug #120 ACK-less FIN sender wedge until timeout", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 0)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      send_timeout = 2_000
      send_task = Task.async(fn -> Tricep.send(socket, "blocked", send_timeout) end)
      wait_for_send_waiters(socket)

      assert {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair
      assert state.tcb.snd_wnd == 0
      assert state.persist_timer_active

      ackless_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          0,
          [:fin],
          5
        )

      DummyLink.inject_packet(link, ackless_fin)
      assert_receive {:dummy_link_packet, ^link, peer_fin_ack_packet}, 1000
      <<_::binary-size(40), peer_fin_ack_segment::binary>> = peer_fin_ack_packet
      peer_fin_ack = Tcp.parse_segment(peer_fin_ack_segment)

      assert peer_fin_ack.flags == [:ack]
      assert peer_fin_ack.seq == state.tcb.snd_nxt
      assert peer_fin_ack.ack == wrap_seq(state.tcb.rcv_nxt + 1)
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:close_wait, %{tcb: %{snd_wnd: 5}, persist_timer_active: false, send_waiters: [_]}} =
               :sys.get_state(socket)

      # Known bug #120: opening SND.WND on an ACK-less direct FIN does not
      # drive send waiters, so the caller remains blocked until its timeout.
      assert Task.await(send_task, 3_000) == {:error, :timeout}
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:close_wait, close_wait_state} = :sys.get_state(socket)
      assert close_wait_state.send_waiters == []
    end

    test "ACK-less zero-window FIN arms persist for buffered send data", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 1)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      assert Tricep.send(socket, "buffered") == :ok
      assert_receive {:dummy_link_packet, ^link, first_data_packet}, 1000
      <<_::binary-size(40), first_data_segment::binary>> = first_data_packet
      assert Tcp.parse_segment(first_data_segment).payload == "b"

      assert {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair
      assert state.tcb.snd_wnd == 1
      refute Tricep.DataBuffer.empty?(state.send_buffer)
      refute state.persist_timer_active

      ackless_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          0,
          [:fin],
          0
        )

      DummyLink.inject_packet(link, ackless_fin)
      assert_receive {:dummy_link_packet, ^link, peer_fin_ack_packet}, 1000
      <<_::binary-size(40), peer_fin_ack_segment::binary>> = peer_fin_ack_packet
      assert Tcp.parse_segment(peer_fin_ack_segment).flags == [:ack]

      assert {:close_wait, close_wait_state} = :sys.get_state(socket)
      assert close_wait_state.tcb.snd_wnd == 0
      refute Tricep.DataBuffer.empty?(close_wait_state.send_buffer)
      assert close_wait_state.persist_timer_active
      assert close_wait_state.persist_timeout_ms == 1_000
    end

    test "prunes fully acknowledged entries when an in-order FIN carries a partial ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, mss: 48)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      assert Tricep.send(socket, :binary.copy("x", 97)) == :ok
      assert_receive {:dummy_link_packet, ^link, first_packet}, 1000
      assert_receive {:dummy_link_packet, ^link, second_packet}, 1000
      assert_receive {:dummy_link_packet, ^link, third_packet}, 1000

      <<_::binary-size(40), first_segment::binary>> = first_packet
      <<_::binary-size(40), second_segment::binary>> = second_packet
      <<_::binary-size(40), third_segment::binary>> = third_packet
      first = Tcp.parse_segment(first_segment)
      second = Tcp.parse_segment(second_segment)
      third = Tcp.parse_segment(third_segment)

      assert {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair
      assert length(state.unacked_segments) == 3

      fin_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          wrap_seq(first.seq + byte_size(first.payload)),
          [:ack, :fin],
          32_768
        )

      DummyLink.inject_packet(link, fin_ack)
      assert_receive {:dummy_link_packet, ^link, _peer_fin_ack_packet}, 1000

      assert {:close_wait, close_wait_state} = :sys.get_state(socket)
      assert close_wait_state.tcb.snd_una == wrap_seq(first.seq + byte_size(first.payload))

      assert Enum.map(close_wait_state.unacked_segments, fn {seq, seq_end, payload, _count} ->
               {seq, seq_end, byte_size(payload)}
             end) == [
               {second.seq, wrap_seq(second.seq + byte_size(second.payload)), 48},
               {third.seq, wrap_seq(third.seq + byte_size(third.payload)), 1}
             ]

      assert close_wait_state.rto_timer_active
      assert close_wait_state.rto_ms == 1000
    end

    test "uses a FIN-carried window update to wake send waiters and cancel persist", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 0)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      send_task = Task.async(fn -> Tricep.send(socket, "woken", :infinity) end)
      wait_for_send_waiters(socket)

      assert {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair
      assert state.persist_timer_active

      fin_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :fin],
          5
        )

      DummyLink.inject_packet(link, fin_ack)
      assert_receive {:dummy_link_packet, ^link, peer_fin_ack_packet}, 1000
      <<_::binary-size(40), peer_fin_ack_segment::binary>> = peer_fin_ack_packet
      assert Tcp.parse_segment(peer_fin_ack_segment).flags == [:ack]

      assert Task.await(send_task, 1000) == :ok
      assert_receive {:dummy_link_packet, ^link, woken_packet}, 1000
      <<_::binary-size(40), woken_segment::binary>> = woken_packet
      assert Tcp.parse_segment(woken_segment).payload == "woken"
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:close_wait, close_wait_state} = :sys.get_state(socket)
      assert close_wait_state.send_waiters == []
      refute close_wait_state.persist_timer_active
      assert close_wait_state.persist_timeout_ms == 1000
    end

    test "processes an in-order FIN-carried ACK across send sequence wrap", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      :sys.replace_state(socket, fn
        {:established, state} ->
          tcb = %{state.tcb | snd_una: 0xFFFFFFFE, snd_nxt: 0xFFFFFFFE}
          {:established, %{state | tcb: tcb}}
      end)

      assert Tricep.send(socket, "wrap") == :ok
      assert_receive {:dummy_link_packet, ^link, outbound_packet}, 1000
      <<_::binary-size(40), outbound_segment::binary>> = outbound_packet
      outbound = Tcp.parse_segment(outbound_segment)
      assert outbound.seq == 0xFFFFFFFE

      assert {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair
      assert state.tcb.snd_nxt == 2

      fin_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :fin],
          32_768
        )

      DummyLink.inject_packet(link, fin_ack)
      assert_receive {:dummy_link_packet, ^link, _peer_fin_ack_packet}, 1000

      assert {:close_wait, close_wait_state} = :sys.get_state(socket)
      assert close_wait_state.tcb.snd_una == 2
      assert close_wait_state.unacked_segments == []
      refute close_wait_state.rto_timer_active
    end

    test "clips an accepted segment at both receive-window edges", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket =
        establish_connection(link, local_addr, remote_addr, open_opts: %{recv_buffer_size: 5})

      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      overlapping_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.tcb.rcv_nxt - 2),
          state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: "abcdefg"
        )

      DummyLink.inject_packet(link, overlapping_segment)
      assert_receive {:dummy_link_packet, ^link, ack_packet}, 1000
      <<_::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert ack.flags == [:ack]
      assert ack.seq == state.tcb.snd_nxt
      assert ack.ack == wrap_seq(state.tcb.rcv_nxt + 5)
      assert ack.window == 0
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100
      assert Tricep.recv(socket, 0, 1000) == {:ok, "cdefg"}
    end

    test "trims receive overlaps across the 32-bit sequence wrap", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket =
        establish_connection(link, local_addr, remote_addr,
          open_opts: %{recv_buffer_size: 4},
          server_seq: 0xFFFFFFFD
        )

      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      {:established, state} = :sys.get_state(socket)
      assert state.tcb.rcv_nxt == 0xFFFFFFFE
      {{_, src_port}, _} = state.pair

      overlapping_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          0xFFFFFFFC,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: "abcdef"
        )

      DummyLink.inject_packet(link, overlapping_segment)
      assert_receive {:dummy_link_packet, ^link, ack_packet}, 1000
      <<_::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert ack.flags == [:ack]
      assert ack.seq == state.tcb.snd_nxt
      assert ack.ack == 2
      assert ack.window == 0
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100
      assert Tricep.recv(socket, 0, 1000) == {:ok, "cdef"}
    end

    test "coalesces queued overlap tails without overcommitting receive capacity", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket =
        establish_connection(link, local_addr, remote_addr, open_opts: %{recv_buffer_size: 2_048})

      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      for {offset, payload, expected_window} <- [{5, "world", 2_043}, {7, "rld!!", 2_041}] do
        segment =
          Tcp.build_segment(
            {{local_addr, @port}, {remote_addr, src_port}},
            wrap_seq(state.tcb.rcv_nxt + offset),
            state.tcb.snd_nxt,
            [:ack, :psh],
            32_768,
            payload: payload
          )

        DummyLink.inject_packet(link, segment)
        assert_receive {:dummy_link_packet, ^link, duplicate_ack_packet}, 1000
        <<_::binary-size(40), duplicate_ack_segment::binary>> = duplicate_ack_packet
        duplicate_ack = Tcp.parse_segment(duplicate_ack_segment)

        assert duplicate_ack.flags == [:ack]
        assert duplicate_ack.seq == state.tcb.snd_nxt
        assert duplicate_ack.ack == state.tcb.rcv_nxt
        assert duplicate_ack.window == expected_window
        refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100
      end

      assert {:established, queued_state} = :sys.get_state(socket)

      assert queued_state.out_of_order_segments == [
               {state.tcb.rcv_nxt + 5, state.tcb.rcv_nxt + 10, "world"},
               {state.tcb.rcv_nxt + 10, state.tcb.rcv_nxt + 12, "!!"}
             ]

      available = queued_state.recv_buffer_size - byte_size(queued_state.recv_buffer) - 7
      assert queued_state.tcb.rcv_wnd <= available
      assert queued_state.tcb.rcv_adv_wnd <= available

      gap_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: "hello"
        )

      DummyLink.inject_packet(link, gap_segment)
      assert_receive {:dummy_link_packet, ^link, final_ack_packet}, 1000
      <<_::binary-size(40), final_ack_segment::binary>> = final_ack_packet
      final_ack = Tcp.parse_segment(final_ack_segment)

      assert final_ack.flags == [:ack]
      assert final_ack.seq == state.tcb.snd_nxt
      assert final_ack.ack == wrap_seq(state.tcb.rcv_nxt + 12)
      assert final_ack.window == 2_036
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100
      assert Tricep.recv(socket, 0, 1000) == {:ok, "helloworld!!"}
    end

    test "recovers a realistic large receive window after reassembly tail eviction", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      max_fragments = ReceiveReassembly.max_fragment_count()
      recv_buffer_size = 4 * 1024 * 1024
      chunk_size = 1460
      first_queued = chunk_size * 2
      front_payload = :binary.copy("a", chunk_size)
      queued_payload = :binary.copy("x", chunk_size)
      last_queued_end = first_queued + max_fragments * chunk_size
      dropped_sequence = last_queued_end + chunk_size

      socket =
        establish_connection(
          link,
          local_addr,
          remote_addr,
          open_opts: %{recv_buffer_size: recv_buffer_size},
          window_scale: 14
        )

      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      {:established, initial_state} = :sys.get_state(socket)
      {{_, src_port}, _} = initial_state.pair

      peer_segment = fn sequence, payload ->
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(initial_state.tcb.rcv_nxt + sequence),
          initial_state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: payload
        )
      end

      for offset <- first_queued..(last_queued_end - chunk_size)//chunk_size do
        DummyLink.inject_packet(link, peer_segment.(offset, queued_payload))
      end

      assert {:established, saturated_state} = :sys.get_state(socket)
      assert length(saturated_state.out_of_order_segments) == max_fragments
      assert saturated_state.recv_buffer_size == recv_buffer_size
      assert saturated_state.tcb.rcv_wnd > div(recv_buffer_size, 2)

      log =
        capture_log(fn ->
          for {sequence, payload} <- [
                {dropped_sequence, :binary.copy("z", chunk_size)},
                {dropped_sequence + chunk_size, :binary.copy("y", chunk_size)},
                {dropped_sequence + chunk_size * 2, :binary.copy("w", chunk_size)}
              ] do
            DummyLink.inject_packet(link, peer_segment.(sequence, payload))
          end
        end)

      assert {:established, dropped_state} = :sys.get_state(socket)
      assert length(dropped_state.out_of_order_segments) == max_fragments
      assert dropped_state.reassembly_eviction_count == 3
      refute log =~ "[warning]"
      assert log =~ "[debug]"
      assert log =~ "cumulative eviction count is 1"
      assert log =~ "cumulative eviction count is 2"
      refute log =~ "cumulative eviction count is 3"

      refute Enum.any?(dropped_state.out_of_order_segments, fn {start, _ending, _payload} ->
               start == wrap_seq(initial_state.tcb.rcv_nxt + dropped_sequence)
             end)

      DummyLink.inject_packet(link, peer_segment.(0, front_payload))

      assert {:established, advanced_state} = :sys.get_state(socket)

      assert advanced_state.tcb.rcv_nxt ==
               wrap_seq(initial_state.tcb.rcv_nxt + byte_size(front_payload))

      assert length(advanced_state.out_of_order_segments) == max_fragments

      DummyLink.inject_packet(
        link,
        peer_segment.(byte_size(front_payload), :binary.copy("b", chunk_size))
      )

      assert {:established, reassembled_state} = :sys.get_state(socket)

      assert reassembled_state.tcb.rcv_nxt ==
               wrap_seq(initial_state.tcb.rcv_nxt + last_queued_end)

      assert reassembled_state.out_of_order_segments == []

      retransmitted_tail =
        :binary.copy("c", chunk_size) <>
          :binary.copy("z", chunk_size) <>
          :binary.copy("y", chunk_size) <>
          :binary.copy("w", chunk_size)

      DummyLink.inject_packet(link, peer_segment.(last_queued_end, retransmitted_tail))

      assert {:established, completed_state} = :sys.get_state(socket)

      assert completed_state.tcb.rcv_nxt ==
               wrap_seq(initial_state.tcb.rcv_nxt + last_queued_end + chunk_size * 4)

      assert completed_state.out_of_order_segments == []
      assert completed_state.reassembly_eviction_count == 3

      expected_payload =
        front_payload <>
          :binary.copy("b", chunk_size) <>
          :binary.copy("x", max_fragments * chunk_size) <>
          retransmitted_tail

      assert Tricep.recv(socket, 0, 1_000) == {:ok, expected_payload}

      drain_packets(max_fragments + 16)

      {{_, src_port}, _} = completed_state.pair

      exact_rst =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          completed_state.tcb.rcv_nxt,
          completed_state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, exact_rst)
      assert {:closed, _} = :sys.get_state(socket)

      reconnect_socket(socket, link, local_addr, remote_addr, 6_000)
      assert {:established, reconnected_state} = :sys.get_state(socket)
      assert reconnected_state.reassembly_eviction_count == 0
    end

    test "reserves an MSS for front recovery under out-of-order byte pressure", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      recv_buffer_size = 65_535

      socket =
        establish_connection(link, local_addr, remote_addr,
          open_opts: %{recv_buffer_size: recv_buffer_size}
        )

      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      {:established, initial_state} = :sys.get_state(socket)
      {{_, src_port}, _} = initial_state.pair
      local_mss = initial_state.tcb.rcv_mss

      peer_segment = fn sequence, payload ->
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(initial_state.tcb.rcv_nxt + sequence),
          initial_state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: payload
        )
      end

      log =
        capture_log(fn ->
          for {start, ending} <- descending_chunks(1, recv_buffer_size, local_mss) do
            DummyLink.inject_packet(link, peer_segment.(start, :binary.copy("x", ending - start)))
          end
        end)

      assert {:established, saturated_state} = :sys.get_state(socket)

      assert saturated_state.tcb.rcv_wnd >= local_mss
      assert saturated_state.reassembly_eviction_count == 1
      refute log =~ "[warning]"
      assert log =~ "[debug]"
      assert log =~ "cumulative eviction count is 1"
      assert length(String.split(log, "cumulative eviction count is 1")) == 2

      DummyLink.inject_packet(link, peer_segment.(0, :binary.copy("a", local_mss)))

      assert {:established, recovered_state} = :sys.get_state(socket)

      assert recovered_state.tcb.rcv_nxt ==
               wrap_seq(initial_state.tcb.rcv_nxt + recv_buffer_size - local_mss)

      assert recovered_state.out_of_order_segments == []

      DummyLink.inject_packet(
        link,
        peer_segment.(recv_buffer_size - local_mss, :binary.copy("x", local_mss))
      )

      assert {:established, completed_state} = :sys.get_state(socket)
      assert completed_state.tcb.rcv_nxt == wrap_seq(initial_state.tcb.rcv_nxt + recv_buffer_size)
      assert completed_state.out_of_order_segments == []

      assert Tricep.recv(socket, 0, 1_000) ==
               {:ok, "a" <> :binary.copy("x", recv_buffer_size - 1)}
    end

    test "reserves all free capacity when it is below the local MSS", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      recv_buffer_size = 1_000

      socket =
        establish_connection(link, local_addr, remote_addr,
          open_opts: %{recv_buffer_size: recv_buffer_size}
        )

      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      {:established, initial_state} = :sys.get_state(socket)
      {{_, src_port}, _} = initial_state.pair

      peer_segment = fn sequence, payload ->
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(initial_state.tcb.rcv_nxt + sequence),
          initial_state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: payload
        )
      end

      log =
        capture_log(fn ->
          DummyLink.inject_packet(link, peer_segment.(1, :binary.copy("x", recv_buffer_size - 1)))
        end)

      assert {:established, queued_state} = :sys.get_state(socket)
      assert queued_state.out_of_order_segments == []
      assert queued_state.reassembly_eviction_count == 1
      assert queued_state.tcb.rcv_wnd == recv_buffer_size
      assert log =~ "[debug]"
      refute log =~ "[warning]"

      DummyLink.inject_packet(link, peer_segment.(0, :binary.copy("a", recv_buffer_size)))

      assert {:established, full_state} = :sys.get_state(socket)
      assert full_state.tcb.rcv_nxt == wrap_seq(initial_state.tcb.rcv_nxt + recv_buffer_size)
      assert byte_size(full_state.recv_buffer) == recv_buffer_size
      assert full_state.tcb.rcv_wnd == 0
    end

    test "drains queued payload and FIN in sequence before entering CLOSE_WAIT", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      queued_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.tcb.rcv_nxt + 5),
          state.tcb.snd_nxt,
          [:ack, :fin],
          32_768,
          payload: "world"
        )

      DummyLink.inject_packet(link, queued_fin)
      assert_receive {:dummy_link_packet, ^link, queued_ack_packet}, 1000
      <<_::binary-size(40), queued_ack_segment::binary>> = queued_ack_packet
      queued_ack = Tcp.parse_segment(queued_ack_segment)

      assert queued_ack.flags == [:ack]
      assert queued_ack.seq == state.tcb.snd_nxt
      assert queued_ack.ack == state.tcb.rcv_nxt
      assert queued_ack.window == state.tcb.rcv_adv_wnd - 5
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:established, queued_state} = :sys.get_state(socket)

      assert queued_state.out_of_order_segments == [
               {state.tcb.rcv_nxt + 5, state.tcb.rcv_nxt + 10, "world"}
             ]

      assert queued_state.out_of_order_fin == state.tcb.rcv_nxt + 10

      gap_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: "hello"
        )

      DummyLink.inject_packet(link, gap_segment)
      assert_receive {:dummy_link_packet, ^link, fin_ack_packet}, 1000
      <<_::binary-size(40), fin_ack_segment::binary>> = fin_ack_packet
      fin_ack = Tcp.parse_segment(fin_ack_segment)

      assert fin_ack.flags == [:ack]
      assert fin_ack.seq == state.tcb.snd_nxt
      assert fin_ack.ack == wrap_seq(state.tcb.rcv_nxt + 11)
      assert fin_ack.window == state.tcb.rcv_adv_wnd - 10
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:close_wait, close_wait_state} = :sys.get_state(socket)
      assert close_wait_state.out_of_order_segments == []
      assert close_wait_state.out_of_order_fin == nil
      assert Tricep.recv(socket, 0, 1000) == {:ok, "helloworld"}
      assert Tricep.recv(socket, 0, 1000) == {:ok, <<>>}
    end

    test "rejects a first FIN marker strictly inside queued data", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      queued_data =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.tcb.rcv_nxt + 5),
          state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: "world"
        )

      DummyLink.inject_packet(link, queued_data)
      assert_receive {:dummy_link_packet, ^link, queued_ack_packet}, 1000
      <<_::binary-size(40), queued_ack_segment::binary>> = queued_ack_packet
      queued_ack = Tcp.parse_segment(queued_ack_segment)

      assert queued_ack.flags == [:ack]
      assert queued_ack.seq == state.tcb.snd_nxt
      assert queued_ack.ack == state.tcb.rcv_nxt
      assert queued_ack.window == state.tcb.rcv_adv_wnd - byte_size("world")
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      conflicting_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.tcb.rcv_nxt + 7),
          state.tcb.snd_nxt,
          [:ack, :fin],
          32_768
        )

      DummyLink.inject_packet(link, conflicting_fin)
      assert_receive {:dummy_link_packet, ^link, fin_ack_packet}, 1000
      <<_::binary-size(40), fin_ack_segment::binary>> = fin_ack_packet
      fin_ack = Tcp.parse_segment(fin_ack_segment)

      assert fin_ack.flags == [:ack]
      assert fin_ack.seq == state.tcb.snd_nxt
      assert fin_ack.ack == state.tcb.rcv_nxt
      assert fin_ack.window == state.tcb.rcv_adv_wnd - byte_size("world")
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:established, queued_state} = :sys.get_state(socket)

      assert queued_state.out_of_order_segments == [
               {state.tcb.rcv_nxt + 5, state.tcb.rcv_nxt + 10, "world"}
             ]

      assert queued_state.out_of_order_fin == nil

      gap_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: "hello"
        )

      DummyLink.inject_packet(link, gap_segment)
      assert_receive {:dummy_link_packet, ^link, final_ack_packet}, 1000
      <<_::binary-size(40), final_ack_segment::binary>> = final_ack_packet
      final_ack = Tcp.parse_segment(final_ack_segment)

      assert final_ack.flags == [:ack]
      assert final_ack.seq == state.tcb.snd_nxt
      assert final_ack.ack == wrap_seq(state.tcb.rcv_nxt + 10)
      assert final_ack.window == state.tcb.rcv_adv_wnd - byte_size("helloworld")
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:established, final_state} = :sys.get_state(socket)
      refute final_state.fin_received
      assert final_state.recv_buffer == "helloworld"

      genuine_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          final_state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :fin],
          32_768
        )

      DummyLink.inject_packet(link, genuine_fin)
      assert_receive {:dummy_link_packet, ^link, genuine_fin_ack_packet}, 1000
      <<_::binary-size(40), genuine_fin_ack_segment::binary>> = genuine_fin_ack_packet
      genuine_fin_ack = Tcp.parse_segment(genuine_fin_ack_segment)

      assert genuine_fin_ack.flags == [:ack]
      assert genuine_fin_ack.seq == state.tcb.snd_nxt
      assert genuine_fin_ack.ack == wrap_seq(state.tcb.rcv_nxt + 11)
      assert genuine_fin_ack.window == state.tcb.rcv_adv_wnd - byte_size("helloworld")
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:close_wait, close_wait_state} = :sys.get_state(socket)
      assert close_wait_state.fin_received
      assert Tricep.recv(socket, 20, 1000) == {:ok, "helloworld"}
      assert Tricep.recv(socket, 0, 1000) == {:ok, <<>>}
    end

    test "full data stream revokes an advisory FIN before a genuine FIN closes", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      pending_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.tcb.rcv_nxt + 5),
          state.tcb.snd_nxt,
          [:ack, :psh, :fin],
          32_768,
          payload: "world"
        )

      DummyLink.inject_packet(link, pending_fin)
      assert_receive {:dummy_link_packet, ^link, pending_fin_ack_packet}, 1000
      <<_::binary-size(40), pending_fin_ack_segment::binary>> = pending_fin_ack_packet
      pending_fin_ack = Tcp.parse_segment(pending_fin_ack_segment)

      assert pending_fin_ack.flags == [:ack]
      assert pending_fin_ack.seq == state.tcb.snd_nxt
      assert pending_fin_ack.ack == state.tcb.rcv_nxt
      assert pending_fin_ack.window == state.tcb.rcv_adv_wnd - 5
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:established, pending_state} = :sys.get_state(socket)
      assert pending_state.out_of_order_fin == wrap_seq(state.tcb.rcv_nxt + 10)

      payload = "helloworld!"

      data_across_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: payload
        )

      DummyLink.inject_packet(link, data_across_fin)
      assert_receive {:dummy_link_packet, ^link, data_ack_packet}, 1000
      <<_::binary-size(40), data_ack_segment::binary>> = data_ack_packet
      data_ack = Tcp.parse_segment(data_ack_segment)

      assert data_ack.flags == [:ack]
      assert data_ack.seq == state.tcb.snd_nxt
      assert data_ack.ack == wrap_seq(state.tcb.rcv_nxt + byte_size(payload))
      assert data_ack.window == state.tcb.rcv_adv_wnd - byte_size(payload)
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:established, final_state} = :sys.get_state(socket)
      refute final_state.fin_received
      assert final_state.out_of_order_fin == nil
      assert final_state.recv_buffer == payload

      genuine_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          final_state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :fin],
          32_768
        )

      DummyLink.inject_packet(link, genuine_fin)
      assert_receive {:dummy_link_packet, ^link, genuine_fin_ack_packet}, 1000
      <<_::binary-size(40), genuine_fin_ack_segment::binary>> = genuine_fin_ack_packet
      genuine_fin_ack = Tcp.parse_segment(genuine_fin_ack_segment)

      assert genuine_fin_ack.flags == [:ack]
      assert genuine_fin_ack.seq == state.tcb.snd_nxt
      assert genuine_fin_ack.ack == wrap_seq(state.tcb.rcv_nxt + byte_size(payload) + 1)
      assert genuine_fin_ack.window == state.tcb.rcv_adv_wnd - byte_size(payload)
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:close_wait, close_wait_state} = :sys.get_state(socket)
      assert close_wait_state.fin_received
      assert Tricep.recv(socket, 20, 1000) == {:ok, payload}
      assert Tricep.recv(socket, 0, 1000) == {:ok, <<>>}
    end

    test "an in-order FIN supersedes a stale advisory FIN marker", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      assert {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      stale_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.tcb.rcv_nxt + 4),
          state.tcb.snd_nxt,
          [:ack, :psh, :fin],
          32_768,
          payload: "o"
        )

      DummyLink.inject_packet(link, stale_fin)
      assert_receive {:dummy_link_packet, ^link, stale_fin_ack_packet}, 1000
      <<_::binary-size(40), stale_fin_ack_segment::binary>> = stale_fin_ack_packet
      stale_fin_ack = Tcp.parse_segment(stale_fin_ack_segment)

      assert stale_fin_ack.flags == [:ack]
      assert stale_fin_ack.seq == state.tcb.snd_nxt
      assert stale_fin_ack.ack == state.tcb.rcv_nxt
      assert stale_fin_ack.window == state.tcb.rcv_adv_wnd - 1
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:established, stale_state} = :sys.get_state(socket)
      assert stale_state.out_of_order_fin == wrap_seq(state.tcb.rcv_nxt + 5)

      real_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :psh, :fin],
          32_768,
          payload: "helloworld"
        )

      DummyLink.inject_packet(link, real_fin)
      assert_receive {:dummy_link_packet, ^link, real_fin_ack_packet}, 1000
      <<_::binary-size(40), real_fin_ack_segment::binary>> = real_fin_ack_packet
      real_fin_ack = Tcp.parse_segment(real_fin_ack_segment)

      assert real_fin_ack.flags == [:ack]
      assert real_fin_ack.seq == state.tcb.snd_nxt
      assert real_fin_ack.ack == wrap_seq(state.tcb.rcv_nxt + 11)
      assert real_fin_ack.window == state.tcb.rcv_adv_wnd - 10
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:close_wait, final_state} = :sys.get_state(socket)
      assert final_state.fin_received
      assert final_state.out_of_order_fin == nil
      assert Tricep.recv(socket, 20, 1000) == {:ok, "helloworld"}
      assert Tricep.recv(socket, 0, 1000) == {:ok, <<>>}
    end

    test "accepts a FIN at the receive-window edge and wakes an oversized recv", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket =
        establish_connection(link, local_addr, remote_addr, open_opts: %{recv_buffer_size: 5})

      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      recv_task = Task.async(fn -> Tricep.recv(socket, 10, 5_000) end)
      wait_for_recv_waiters(socket)

      data = "hello"

      data_and_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :psh, :fin],
          32_768,
          payload: data
        )

      DummyLink.inject_packet(link, data_and_fin)
      assert_receive {:dummy_link_packet, ^link, data_ack_packet}, 1000
      <<_::binary-size(40), data_ack_segment::binary>> = data_ack_packet
      data_ack = Tcp.parse_segment(data_ack_segment)

      assert data_ack.flags == [:ack]
      assert data_ack.seq == state.tcb.snd_nxt
      assert data_ack.ack == wrap_seq(state.tcb.rcv_nxt + byte_size(data) + 1)
      assert data_ack.window == byte_size(data)
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:close_wait, close_wait_state} = :sys.get_state(socket)
      assert close_wait_state.fin_received
      assert close_wait_state.out_of_order_fin == nil
      refute close_wait_state.rto_timer_active
      assert Task.await(recv_task, 1000) == {:ok, data}
      assert Tricep.recv(socket, 0, 1000) == {:ok, <<>>}
    end

    test "processes an ACK that drains a previously queued FIN", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      assert Tricep.send(socket, "outbound") == :ok
      assert_receive {:dummy_link_packet, ^link, outbound_packet}, 1000
      <<_::binary-size(40), outbound_segment::binary>> = outbound_packet
      outbound = Tcp.parse_segment(outbound_segment)

      assert {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair
      assert state.unacked_segments != []
      assert state.rto_timer_active

      queued_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.tcb.rcv_nxt + 5),
          state.tcb.snd_una,
          [:ack, :psh, :fin],
          32_768,
          payload: "world"
        )

      DummyLink.inject_packet(link, queued_fin)
      assert_receive {:dummy_link_packet, ^link, queued_fin_ack_packet}, 1000
      <<_::binary-size(40), queued_fin_ack_segment::binary>> = queued_fin_ack_packet
      queued_fin_ack = Tcp.parse_segment(queued_fin_ack_segment)

      assert queued_fin_ack.flags == [:ack]
      assert queued_fin_ack.seq == state.tcb.snd_nxt
      assert queued_fin_ack.ack == state.tcb.rcv_nxt
      assert queued_fin_ack.window == state.tcb.rcv_adv_wnd - 5
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      gap_and_full_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          wrap_seq(outbound.seq + byte_size(outbound.payload)),
          [:ack, :psh],
          32_768,
          payload: "hello"
        )

      DummyLink.inject_packet(link, gap_and_full_ack)
      assert_receive {:dummy_link_packet, ^link, final_ack_packet}, 1000
      <<_::binary-size(40), final_ack_segment::binary>> = final_ack_packet
      final_ack = Tcp.parse_segment(final_ack_segment)

      assert final_ack.flags == [:ack]
      assert final_ack.seq == state.tcb.snd_nxt
      assert final_ack.ack == wrap_seq(state.tcb.rcv_nxt + 11)
      assert final_ack.window == state.tcb.rcv_adv_wnd - 10
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:close_wait, final_state} = :sys.get_state(socket)
      assert final_state.fin_received
      assert final_state.tcb.snd_una == state.tcb.snd_nxt
      assert final_state.unacked_segments == []
      refute final_state.rto_timer_active
      assert final_state.send_waiters == []
      refute final_state.persist_timer_active
      assert Tricep.recv(socket, 0, 1000) == {:ok, "helloworld"}
      assert Tricep.recv(socket, 0, 1000) == {:ok, <<>>}
    end

    test "drops a queued bare FIN until it is retransmitted in order", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      queued_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.tcb.rcv_nxt + 5),
          state.tcb.snd_nxt,
          [:ack, :fin],
          32_768
        )

      DummyLink.inject_packet(link, queued_fin)
      assert_receive {:dummy_link_packet, ^link, queued_ack_packet}, 1000
      <<_::binary-size(40), queued_ack_segment::binary>> = queued_ack_packet
      queued_ack = Tcp.parse_segment(queued_ack_segment)

      assert queued_ack.flags == [:ack]
      assert queued_ack.seq == state.tcb.snd_nxt
      assert queued_ack.ack == state.tcb.rcv_nxt
      assert queued_ack.window == state.tcb.rcv_adv_wnd
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:established, %{out_of_order_fin: nil}} = :sys.get_state(socket)

      gap_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: "hello"
        )

      DummyLink.inject_packet(link, gap_segment)
      assert_receive {:dummy_link_packet, ^link, fin_ack_packet}, 1000
      <<_::binary-size(40), fin_ack_segment::binary>> = fin_ack_packet
      fin_ack = Tcp.parse_segment(fin_ack_segment)

      assert fin_ack.flags == [:ack]
      assert fin_ack.seq == state.tcb.snd_nxt
      assert fin_ack.ack == wrap_seq(state.tcb.rcv_nxt + 5)
      assert fin_ack.window == state.tcb.rcv_adv_wnd - 5
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:established, _} = :sys.get_state(socket)
      assert Tricep.recv(socket, 0, 1000) == {:ok, "hello"}

      assert_receive {:dummy_link_packet, ^link, window_update_packet}, 1000
      <<_::binary-size(40), window_update_segment::binary>> = window_update_packet
      window_update = Tcp.parse_segment(window_update_segment)
      assert window_update.flags == [:ack]
      assert window_update.ack == wrap_seq(state.tcb.rcv_nxt + 5)

      retransmitted_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.tcb.rcv_nxt + 5),
          state.tcb.snd_nxt,
          [:ack, :fin],
          32_768
        )

      DummyLink.inject_packet(link, retransmitted_fin)
      assert_receive {:dummy_link_packet, ^link, retransmitted_ack_packet}, 1000
      <<_::binary-size(40), retransmitted_ack_segment::binary>> = retransmitted_ack_packet
      retransmitted_ack = Tcp.parse_segment(retransmitted_ack_segment)

      assert retransmitted_ack.flags == [:ack]
      assert retransmitted_ack.ack == wrap_seq(state.tcb.rcv_nxt + 6)
      assert {:close_wait, _} = :sys.get_state(socket)
      assert Tricep.recv(socket, 0, 1000) == {:ok, <<>>}
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
          state.tcb.irs + 1,
          wrap_seq(state.tcb.snd_nxt + 1),
          [:ack, :psh],
          32768,
          payload: "must not deliver"
        )

      DummyLink.inject_packet(link, invalid_ack_segment)

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert :ack in ack.flags
      assert ack.seq == state.tcb.snd_nxt
      assert ack.ack == state.tcb.rcv_nxt
      assert Tricep.recv(socket, 0, 100) == {:error, :timeout}

      {:established, new_state} = :sys.get_state(socket)
      assert new_state.tcb.rcv_nxt == state.tcb.rcv_nxt
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
      assert new_state.tcb.rcv_nxt == state.tcb.rcv_nxt

      # Can still recv properly formatted data
      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
      socket = establish_connection(link, local_addr, remote_addr, mss: 48, window: 1)

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
          state.tcb.irs + 1,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      # Should be in TIME_WAIT
      {:time_wait, time_wait_state} = :sys.get_state(socket)
      assert Tcp.parse_segment(fin_segment).seq == wrap_seq(time_wait_state.tcb.rcv_nxt - 1)

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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 1,
          wrap_seq(state.tcb.snd_nxt + 1),
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:established, new_state} = :sys.get_state(socket)

      assert new_state.tcb.snd_una == state.tcb.snd_una
      assert new_state.tcb.snd_nxt == state.tcb.snd_nxt
      assert new_state.tcb.rcv_nxt == state.tcb.rcv_nxt
      assert new_state.recv_buffer == state.recv_buffer
      assert new_state.fin_received == state.fin_received
      assert new_state.tcb.snd_wnd == state.tcb.snd_wnd

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert :ack in ack.flags
      assert ack.seq == state.tcb.snd_nxt
      assert ack.ack == state.tcb.rcv_nxt
      refute_receive {:dummy_link_packet, _link, _unexpected_packet}, 100
    end

    test "public recv returns a short final explicit-length read then EOF", %{
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

      final_data = "Final data"
      requested_length = byte_size(final_data) + 1

      # Send data with FIN before any recv call, so the final data is buffered.
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
          [:fin, :ack],
          32768,
          payload: final_data
        )

      DummyLink.inject_packet(link, fin_segment)

      # An explicit length normally waits for exactly n bytes, but EOF returns
      # the buffered tail and the caller can identify the short final read.
      assert {:ok, received} = Tricep.recv(socket, requested_length, 100)
      assert received == final_data
      assert byte_size(received) < requested_length

      # A subsequent call distinguishes EOF from the short final read.
      assert Tricep.recv(socket, requested_length, 100) == {:ok, <<>>}
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      # Should be closed
      {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)
    end

    test "FIN+ACK in FIN_WAIT_1 goes directly to TIME_WAIT", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      Process.unlink(socket)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      assert {:established, %{rto_ms: 100}} =
               :sys.replace_state(socket, fn
                 {:established, current_state} ->
                   {:established, %{current_state | rto_ms: 100}}
               end)

      # Close to enter FIN_WAIT_1
      assert Tricep.close(socket) == :ok

      # Drain FIN
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      {:fin_wait_1, _} = :sys.get_state(socket)

      # Send FIN+ACK (acknowledging our FIN and sending their FIN)
      fin_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_ack_segment)

      # Should go directly to TIME_WAIT (skipping FIN_WAIT_2) after the
      # carried ACK has completed the FIN's send-side bookkeeping.
      {:time_wait, time_wait_state} = :sys.get_state(socket)
      assert time_wait_state.unacked_segments == []
      refute time_wait_state.rto_timer_active

      # Should have sent ACK for peer's FIN
      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_::binary-size(40), ack_seg::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_seg)
      assert ack.flags == [:ack]
      assert ack.ack == state.tcb.rcv_nxt + 1
      refute_receive {:dummy_link_packet, _link, _unexpected_packet}, 100

      Process.sleep(200)
      assert Process.alive?(socket)

      assert {:time_wait, %{unacked_segments: [], rto_timer_active: false}} =
               :sys.get_state(socket)
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      # Should go to CLOSING (simultaneous close), retaining our unacknowledged FIN.
      {:closing, closing_state} = :sys.get_state(socket)
      assert [{_seq, _seq_end, :fin, 0}] = closing_state.unacked_segments
      assert closing_state.rto_timer_active

      # Should have sent ACK for peer's FIN
      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_::binary-size(40), ack_seg::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_seg)
      assert ack.flags == [:ack]
      assert ack.ack == state.tcb.rcv_nxt + 1
      refute_receive {:dummy_link_packet, _link, _unexpected_packet}, 100
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, wrong_ack)

      # Should still be in FIN_WAIT_1 (wrong ACK ignored)
      {:fin_wait_1, _} = :sys.get_state(socket)
    end

    test "preserves state when a no-op segment would otherwise start persist", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 1)
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, established_state} = :sys.get_state(socket)
      {{_, src_port}, _} = established_state.pair

      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      :sys.replace_state(socket, fn
        {:fin_wait_1, state} ->
          send_buffer = Tricep.DataBuffer.append(state.send_buffer, "pending")
          {:fin_wait_1, %{state | send_buffer: send_buffer, persist_timer_active: false}}
      end)

      {:fin_wait_1, before_state} = :sys.get_state(socket)
      refute before_state.persist_timer_active
      assert before_state.tcb.snd_wnd == 1

      no_op_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          before_state.tcb.rcv_nxt,
          0,
          [],
          0
        )

      DummyLink.inject_packet(link, no_op_segment)

      assert {:fin_wait_1, after_state} = :sys.get_state(socket)
      assert after_state.tcb.snd_wnd == before_state.tcb.snd_wnd
      assert after_state.persist_timer_active == before_state.persist_timer_active
      assert after_state.persist_timeout_ms == before_state.persist_timeout_ms
      assert after_state.send_buffer == before_state.send_buffer
      refute_receive {:dummy_link_packet, _link, _packet}, 100
    end

    test "ACK-less payload with no recv waiter keeps the historical discarded state", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      {:established, established_state} = :sys.get_state(socket)
      {{_, src_port}, _} = established_state.pair

      assert Tricep.shutdown(socket, :write) == :ok
      assert_receive {:dummy_link_packet, ^link, _our_fin}, 1000
      assert {:fin_wait_1, before_state} = :sys.get_state(socket)

      payload = "discarded"

      ackless_payload =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          before_state.tcb.rcv_nxt,
          0,
          [:psh],
          0,
          payload: payload
        )

      DummyLink.inject_packet(link, ackless_payload)

      assert_receive {:dummy_link_packet, ^link, response_packet}, 1000
      <<_::binary-size(40), response_segment::binary>> = response_packet
      response = Tcp.parse_segment(response_segment)

      assert response.flags == [:ack]
      assert response.seq == before_state.tcb.snd_nxt
      assert response.ack == before_state.tcb.rcv_nxt
      assert response.window == before_state.tcb.rcv_adv_wnd
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:fin_wait_1, after_state} = :sys.get_state(socket)
      assert after_state.tcb.rcv_nxt == before_state.tcb.rcv_nxt
      assert after_state.recv_buffer == <<>>
      assert after_state.tcb.snd_wnd == before_state.tcb.snd_wnd
      assert after_state.persist_timer_active == before_state.persist_timer_active
      assert after_state.persist_timeout_ms == before_state.persist_timeout_ms
    end

    test "ACK-less in-order payload cannot drain queued data or notify receivers", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      {:established, established_state} = :sys.get_state(socket)
      {{_, src_port}, _} = established_state.pair

      assert Tricep.shutdown(socket, :write) == :ok
      assert_receive {:dummy_link_packet, ^link, _our_fin}, 1000

      assert {:fin_wait_1, before_state} = :sys.get_state(socket)

      queued_data =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(before_state.tcb.rcv_nxt + 5),
          before_state.tcb.snd_una,
          [:ack, :psh],
          32_768,
          payload: "world"
        )

      DummyLink.inject_packet(link, queued_data)
      assert_receive {:dummy_link_packet, ^link, queued_ack_packet}, 1000
      <<_::binary-size(40), queued_ack_segment::binary>> = queued_ack_packet
      queued_ack = Tcp.parse_segment(queued_ack_segment)

      assert queued_ack.flags == [:ack]
      assert queued_ack.seq == before_state.tcb.snd_nxt
      assert queued_ack.ack == before_state.tcb.rcv_nxt
      assert queued_ack.window == before_state.tcb.rcv_adv_wnd - byte_size("world")
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:fin_wait_1, queued_state} = :sys.get_state(socket)

      assert queued_state.out_of_order_segments == [
               {wrap_seq(before_state.tcb.rcv_nxt + 5), wrap_seq(before_state.tcb.rcv_nxt + 10),
                "world"}
             ]

      recv_task = Task.async(fn -> Tricep.recv(socket, 0, 5_000) end)
      wait_for_recv_waiters(socket)
      assert {:select, {:select_info, :recv, ref}} = Tricep.recv(socket, 0, :nowait)

      assert {:fin_wait_1, waiting_state} = :sys.get_state(socket)
      assert length(waiting_state.recv_waiters) == 1
      assert length(waiting_state.recv_selects) == 1

      ackless_payload =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          waiting_state.tcb.rcv_nxt,
          0,
          [:psh],
          0,
          payload: "hello"
        )

      DummyLink.inject_packet(link, ackless_payload)

      assert_receive {:dummy_link_packet, ^link, response_packet}, 1000
      <<_::binary-size(40), response_segment::binary>> = response_packet
      response = Tcp.parse_segment(response_segment)

      assert response.flags == [:ack]
      assert response.seq == waiting_state.tcb.snd_nxt
      assert response.ack == waiting_state.tcb.rcv_nxt
      assert response.window == waiting_state.tcb.rcv_adv_wnd
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100
      refute_receive {:"$socket", ^socket, :select, ^ref}, 100
      assert Task.yield(recv_task, 50) == nil

      assert {:fin_wait_1, after_state} = :sys.get_state(socket)
      assert after_state.tcb.rcv_nxt == waiting_state.tcb.rcv_nxt
      assert after_state.recv_buffer == <<>>
      assert after_state.out_of_order_segments == waiting_state.out_of_order_segments
      assert after_state.out_of_order_fin == waiting_state.out_of_order_fin
      assert after_state.recv_waiters == waiting_state.recv_waiters
      assert after_state.recv_selects == waiting_state.recv_selects
      assert after_state.tcb.snd_wnd == waiting_state.tcb.snd_wnd

      Task.shutdown(recv_task, :brutal_kill)
    end

    test "queued FIN and gap-fill ACK of our FIN transition directly to TIME_WAIT", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

      assert Tricep.shutdown(socket, :write) == :ok
      assert_receive {:dummy_link_packet, ^link, our_fin_packet}, 1000
      <<_::binary-size(40), our_fin_segment::binary>> = our_fin_packet
      our_fin = Tcp.parse_segment(our_fin_segment)

      assert {:fin_wait_1, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair
      assert our_fin.seq == wrap_seq(state.tcb.snd_nxt - 1)

      queued_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.tcb.rcv_nxt + 5),
          state.tcb.snd_una,
          [:ack, :psh, :fin],
          32_768,
          payload: "world"
        )

      DummyLink.inject_packet(link, queued_fin)
      assert_receive {:dummy_link_packet, ^link, queued_fin_ack_packet}, 1000
      <<_::binary-size(40), queued_fin_ack_segment::binary>> = queued_fin_ack_packet
      queued_fin_ack = Tcp.parse_segment(queued_fin_ack_segment)

      assert queued_fin_ack.flags == [:ack]
      assert queued_fin_ack.seq == state.tcb.snd_nxt
      assert queued_fin_ack.ack == state.tcb.rcv_nxt
      assert queued_fin_ack.window == state.tcb.rcv_adv_wnd - 5
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:fin_wait_1, queued_state} = :sys.get_state(socket)
      assert queued_state.out_of_order_fin == wrap_seq(state.tcb.rcv_nxt + 10)
      assert queued_state.unacked_segments != []
      assert queued_state.rto_timer_active

      gap_and_fin_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:ack, :psh],
          32_768,
          payload: "hello"
        )

      DummyLink.inject_packet(link, gap_and_fin_ack)
      assert_receive {:dummy_link_packet, ^link, final_ack_packet}, 1000
      <<_::binary-size(40), final_ack_segment::binary>> = final_ack_packet
      final_ack = Tcp.parse_segment(final_ack_segment)

      assert final_ack.flags == [:ack]
      assert final_ack.seq == state.tcb.snd_nxt
      assert final_ack.ack == wrap_seq(state.tcb.rcv_nxt + 11)
      assert final_ack.window == state.tcb.rcv_adv_wnd - 10
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:time_wait, time_wait_state} = :sys.get_state(socket)
      assert time_wait_state.fin_received
      assert time_wait_state.unacked_segments == []
      refute time_wait_state.rto_timer_active
      assert time_wait_state.out_of_order_fin == nil
      assert Tricep.recv(socket, 0, 1000) == {:ok, "helloworld"}
      assert Tricep.recv(socket, 0, 1000) == {:ok, <<>>}
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
          state.tcb.irs + 1,
          data_ack,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      {:fin_wait_1, acked_state} = :sys.get_state(socket)
      assert acked_state.tcb.snd_una == data_ack
      assert [{fin_seq, fin_end, :fin, _count}] = acked_state.unacked_segments
      assert fin_seq == fin.seq
      assert fin_end == wrap_seq(fin.seq + 1)
      assert acked_state.rto_timer_active == true

      fin_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          acked_state.tcb.snd_nxt,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      {:fin_wait_2, _} = :sys.get_state(socket)

      # Send RST
      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      {:fin_wait_2, _} = :sys.get_state(socket)

      # Send data (half-close allows peer to still send)
      data_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
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

    test "ACK-less in-order data is acknowledged without waking receivers", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)

      {_established_state, _src_port} =
        shutdown_write_to_fin_wait_2(socket, link, local_addr, remote_addr)

      assert {:fin_wait_2, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      recv_task = Task.async(fn -> Tricep.recv(socket, 0, 5_000) end)
      wait_for_recv_waiters(socket)
      assert {:select, {:select_info, :recv, ref}} = Tricep.recv(socket, 0, :nowait)

      assert {:fin_wait_2, before_state} = :sys.get_state(socket)
      assert length(before_state.recv_waiters) == 1
      assert length(before_state.recv_selects) == 1

      ackless_data =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt,
          [:psh],
          0,
          payload: "must not deliver"
        )

      DummyLink.inject_packet(link, ackless_data)
      assert_receive {:dummy_link_packet, ^link, ack_packet}, 1000
      <<_::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert ack.flags == [:ack]
      assert ack.payload == <<>>
      assert ack.seq == before_state.tcb.snd_nxt
      assert ack.ack == before_state.tcb.rcv_nxt
      assert ack.window == before_state.tcb.rcv_adv_wnd
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100
      refute_receive {:"$socket", ^socket, :select, ^ref}, 100
      assert Task.yield(recv_task, 50) == nil

      assert {:fin_wait_2, after_state} = :sys.get_state(socket)
      assert after_state.tcb.rcv_nxt == before_state.tcb.rcv_nxt
      assert after_state.recv_buffer == before_state.recv_buffer
      assert after_state.out_of_order_segments == before_state.out_of_order_segments
      assert after_state.out_of_order_fin == before_state.out_of_order_fin
      assert after_state.recv_waiters == before_state.recv_waiters
      assert after_state.recv_selects == before_state.recv_selects
      assert after_state.tcb.snd_wnd == 0
      assert after_state.tcb.snd_una == before_state.tcb.snd_una
      assert after_state.tcb.snd_nxt == before_state.tcb.snd_nxt
      refute after_state.persist_timer_active

      Task.shutdown(recv_task, :brutal_kill)
    end

    test "ACK-less left-overlapping data is acknowledged without waking receivers", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      shutdown_write_to_fin_wait_2(socket, link, local_addr, remote_addr)

      assert {:fin_wait_2, state} = :sys.get_state(socket)

      assert_ackless_payloads_preserve_receive_state(
        socket,
        link,
        local_addr,
        remote_addr,
        :fin_wait_2,
        [
          {wrap_seq(state.tcb.rcv_nxt - 1), [:psh], "ab"},
          {wrap_seq(state.tcb.rcv_nxt - 2), [:psh, :fin], "abcd"}
        ]
      )
    end

    test "ACK-less left-overlapping data is rejected across sequence wrap", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, server_seq: 0xFFFFFFFD)
      on_exit(fn -> stop_socket(socket) end)
      shutdown_write_to_fin_wait_2(socket, link, local_addr, remote_addr)

      assert {:fin_wait_2, %{tcb: %{rcv_nxt: 0xFFFFFFFE}} = state} = :sys.get_state(socket)

      assert_ackless_payloads_preserve_receive_state(
        socket,
        link,
        local_addr,
        remote_addr,
        :fin_wait_2,
        [
          {wrap_seq(state.tcb.rcv_nxt - 1), [:psh], "ab"},
          {wrap_seq(state.tcb.rcv_nxt - 2), [:psh, :fin], "abcd"}
        ]
      )
    end

    test "does not latch an ACK-less out-of-order bare or payload FIN", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      shutdown_write_to_fin_wait_2(socket, link, local_addr, remote_addr)

      assert_ackless_out_of_order_fin_does_not_close(
        socket,
        link,
        local_addr,
        remote_addr,
        :fin_wait_2
      )
    end

    test "ACK-less future payload invalidates an advisory FIN across sequence wrap", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, server_seq: 0xFFFFFFFD)
      on_exit(fn -> stop_socket(socket) end)
      shutdown_write_to_fin_wait_2(socket, link, local_addr, remote_addr)

      assert_ackless_future_payload_invalidates_advisory_fin(
        socket,
        link,
        local_addr,
        remote_addr,
        :fin_wait_2
      )
    end

    test "queues sequence-acceptable data in FIN_WAIT_2 until its gap arrives", %{
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      {:fin_wait_2, _} = :sys.get_state(socket)

      # Send segment with wrong seq (out of order)
      wrong_seq =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1000,
          state.tcb.snd_nxt + 1,
          [:ack, :psh],
          32768,
          payload: "Wrong seq"
        )

      DummyLink.inject_packet(link, wrong_seq)

      assert_receive {:dummy_link_packet, _link, ack_packet}, 1000
      <<_ip_header::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert :ack in ack.flags
      assert ack.ack == state.tcb.irs + 1

      # The half-closed receive path uses the same bounded reassembly queue.
      {:fin_wait_2, fin_wait_2_state} = :sys.get_state(socket)
      assert fin_wait_2_state.recv_buffer == <<>>

      assert fin_wait_2_state.out_of_order_segments == [
               {state.tcb.irs + 1000, state.tcb.irs + 1009, "Wrong seq"}
             ]
    end

    test "drains an out-of-order FIN in FIN_WAIT_2 after its data gap arrives", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)

      {state, src_port} = shutdown_write_to_fin_wait_2(socket, link, local_addr, remote_addr)

      queued_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(state.tcb.rcv_nxt + 5),
          state.tcb.snd_nxt + 1,
          [:ack, :fin],
          32_768,
          payload: "world"
        )

      DummyLink.inject_packet(link, queued_fin)
      assert_receive {:dummy_link_packet, ^link, queued_ack_packet}, 1000
      <<_::binary-size(40), queued_ack_segment::binary>> = queued_ack_packet
      queued_ack = Tcp.parse_segment(queued_ack_segment)

      assert queued_ack.flags == [:ack]
      assert queued_ack.seq == state.tcb.snd_nxt + 1
      assert queued_ack.ack == state.tcb.rcv_nxt
      assert queued_ack.window == state.tcb.rcv_adv_wnd - 5
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:fin_wait_2, queued_state} = :sys.get_state(socket)

      assert queued_state.out_of_order_segments == [
               {state.tcb.rcv_nxt + 5, state.tcb.rcv_nxt + 10, "world"}
             ]

      assert queued_state.out_of_order_fin == state.tcb.rcv_nxt + 10

      gap_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.rcv_nxt,
          state.tcb.snd_nxt + 1,
          [:ack, :psh],
          32_768,
          payload: "hello"
        )

      DummyLink.inject_packet(link, gap_segment)
      assert_receive {:dummy_link_packet, ^link, fin_ack_packet}, 1000
      <<_::binary-size(40), fin_ack_segment::binary>> = fin_ack_packet
      fin_ack = Tcp.parse_segment(fin_ack_segment)

      assert fin_ack.flags == [:ack]
      assert fin_ack.seq == state.tcb.snd_nxt + 1
      assert fin_ack.ack == wrap_seq(state.tcb.rcv_nxt + 11)
      assert fin_ack.window == state.tcb.rcv_adv_wnd - 10
      refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

      assert {:time_wait, time_wait_state} = :sys.get_state(socket)
      assert time_wait_state.out_of_order_segments == []
      assert time_wait_state.out_of_order_fin == nil
      assert Tricep.recv(socket, 20, 1000) == {:ok, "helloworld"}
      assert Tricep.recv(socket, 0, 1000) == {:ok, <<>>}
    end
  end

  describe "TIME_WAIT state" do
    test "exact RST leaves TIME_WAIT without responding", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {_established_state, time_wait_state} =
        enter_time_wait(socket, link, local_addr, remote_addr)

      {{_, src_port}, _} = time_wait_state.pair

      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          time_wait_state.tcb.rcv_nxt,
          time_wait_state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      refute_receive {:dummy_link_packet, ^link, _}, 100
      assert {:time_wait, _state} = :sys.get_state(socket)
    end

    test "unexpected SYN in TIME_WAIT is silently dropped", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {_established_state, time_wait_state} =
        enter_time_wait(socket, link, local_addr, remote_addr)

      {{_, src_port}, _} = time_wait_state.pair

      syn_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(time_wait_state.tcb.rcv_nxt - 1),
          0,
          [:syn, :fin],
          0
        )

      DummyLink.inject_packet(link, syn_segment)

      refute_receive {:dummy_link_packet, ^link, _}, 100
      assert {:time_wait, _state} = :sys.get_state(socket)
    end

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
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      {:fin_wait_2, _} = :sys.get_state(socket)

      # Send FIN from peer
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:time_wait, time_wait_state} = :sys.get_state(socket)
      assert Tcp.parse_segment(fin_segment).seq == wrap_seq(time_wait_state.tcb.rcv_nxt - 1)

      # Drain ACK for peer's FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      wait_for_state_name(socket, :closed, 2_500)
    end

    test "bare FIN retransmit in TIME_WAIT is re-ACKed", %{
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      # Send FIN from peer
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:time_wait, time_wait_state} = :sys.get_state(socket)
      assert Tcp.parse_segment(fin_segment).seq == wrap_seq(time_wait_state.tcb.rcv_nxt - 1)

      # Drain first ACK
      assert_receive {:dummy_link_packet, _link, _first_ack}, 1000

      # Send FIN again (simulating retransmit because peer didn't get our ACK)
      DummyLink.inject_packet(link, fin_segment)

      # Should re-ACK
      assert_receive {:dummy_link_packet, _link, re_ack_packet}, 1000
      <<_::binary-size(40), re_ack_seg::binary>> = re_ack_packet
      re_ack = Tcp.parse_segment(re_ack_seg)
      assert re_ack.flags == [:ack]
      assert re_ack.ack == time_wait_state.tcb.rcv_nxt

      # Should still be in TIME_WAIT
      {:time_wait, _} = :sys.get_state(socket)
      refute_receive {:dummy_link_packet, ^link, _}, 100
    end

    test "data plus FIN retransmit in TIME_WAIT is re-ACKed", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      payload = "final payload"
      socket = establish_connection(link, local_addr, remote_addr)
      assert_receive {:dummy_link_packet, ^link, _ack_packet}, 1000

      {established_state, time_wait_state} =
        enter_time_wait(socket, link, local_addr, remote_addr, payload: payload)

      assert time_wait_state.tcb.rcv_nxt ==
               wrap_seq(established_state.tcb.irs + 1 + byte_size(payload) + 1)

      {{_, src_port}, _} = time_wait_state.pair

      retransmitted_data_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          established_state.tcb.irs + 1,
          time_wait_state.tcb.snd_nxt,
          [:fin, :ack],
          32768,
          payload: payload
        )

      retransmit = Tcp.parse_segment(retransmitted_data_fin)

      assert wrap_seq(retransmit.seq + byte_size(retransmit.payload)) ==
               wrap_seq(time_wait_state.tcb.rcv_nxt - 1)

      DummyLink.inject_packet(link, retransmitted_data_fin)

      assert_receive {:dummy_link_packet, ^link, ack_packet}, 1000
      <<_::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert ack.flags == [:ack]
      assert ack.ack == time_wait_state.tcb.rcv_nxt
      assert {:time_wait, %{tcb: %{rcv_nxt: rcv_nxt}}} = :sys.get_state(socket)
      assert rcv_nxt == time_wait_state.tcb.rcv_nxt
      refute_receive {:dummy_link_packet, ^link, _}, 100
    end

    test "out-of-window bare ACK in TIME_WAIT is silently dropped", %{
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, ack_segment)

      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:time_wait, time_wait_state} = :sys.get_state(socket)

      # Drain first ACK
      assert_receive {:dummy_link_packet, _link, _first_ack}, 1000

      # Send an arbitrary out-of-window non-FIN segment.
      just_ack =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(time_wait_state.tcb.rcv_nxt + time_wait_state.tcb.rcv_wnd),
          state.tcb.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, just_ack)

      # Should not send any response (no new packet)
      refute_receive {:dummy_link_packet, _link, _}, 100

      # Should still be in TIME_WAIT
      {:time_wait, _} = :sys.get_state(socket)
    end

    test "unrelated FIN in TIME_WAIT is silently dropped", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      assert_receive {:dummy_link_packet, ^link, _ack_packet}, 1000

      {_established_state, time_wait_state} =
        enter_time_wait(socket, link, local_addr, remote_addr)

      {{_, src_port}, _} = time_wait_state.pair

      unrelated_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          time_wait_state.tcb.rcv_nxt,
          time_wait_state.tcb.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, unrelated_fin)

      refute_receive {:dummy_link_packet, ^link, _}, 100
      assert {:time_wait, _state} = :sys.get_state(socket)
    end

    test "payload-bearing FIN retransmit crossing the wrap boundary is re-ACKed", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      assert_receive {:dummy_link_packet, ^link, _ack_packet}, 1000

      {_established_state, time_wait_state} =
        enter_time_wait(socket, link, local_addr, remote_addr)

      wrapped_time_wait_state =
        :sys.replace_state(socket, fn {:time_wait, state} ->
          {:time_wait, %{state | tcb: %{state.tcb | rcv_nxt: 1}}}
        end)

      assert {:time_wait, %{tcb: %{rcv_nxt: 1}}} = wrapped_time_wait_state
      {{_, src_port}, _} = time_wait_state.pair

      payload = <<0xAA, 0xBB>>

      retransmitted_fin =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          0xFFFFFFFE,
          time_wait_state.tcb.snd_nxt,
          [:fin, :ack],
          32768,
          payload: payload
        )

      retransmit = Tcp.parse_segment(retransmitted_fin)
      assert retransmit.seq == 0xFFFFFFFE
      assert retransmit.payload == payload
      assert wrap_seq(retransmit.seq + byte_size(retransmit.payload)) == 0

      DummyLink.inject_packet(link, retransmitted_fin)

      assert_receive {:dummy_link_packet, ^link, ack_packet}, 1000
      <<_::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert ack.flags == [:ack]
      assert ack.ack == 1
      assert {:time_wait, %{tcb: %{rcv_nxt: 1}}} = :sys.get_state(socket)
      refute_receive {:dummy_link_packet, ^link, _}, 100
    end
  end

  describe "CLOSING state" do
    test "RST in CLOSING closes connection", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      Process.unlink(socket)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      assert {:established, %{rto_ms: 100}} =
               :sys.replace_state(socket, fn
                 {:established, current_state} ->
                   {:established, %{current_state | rto_ms: 100}}
               end)

      # Close to enter FIN_WAIT_1
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      {:fin_wait_1, _} = :sys.get_state(socket)

      # Send FIN without ACK of our FIN (simultaneous close)
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 2,
          state.tcb.snd_nxt + 1,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)
      assert {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)

      # The FIN RTO armed before simultaneous close was cancelled as well.
      Process.sleep(200)
      assert Process.alive?(socket)
    end

    test "in-window non-exact RST in CLOSING gets a challenge ACK", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)
      assert {:closing, closing_state} = :sys.get_state(socket)
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          wrap_seq(closing_state.tcb.rcv_nxt + 1),
          closing_state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      assert_challenge_ack(link, closing_state)
      assert {:closing, _state} = :sys.get_state(socket)
    end

    test "ACK of our FIN in CLOSING goes to TIME_WAIT", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      Process.unlink(socket)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      assert {:established, %{rto_ms: 100}} =
               :sys.replace_state(socket, fn
                 {:established, current_state} ->
                   {:established, %{current_state | rto_ms: 100}}
               end)

      # Close to enter FIN_WAIT_1
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

      {:fin_wait_1, _} = :sys.get_state(socket)

      # Send FIN without ACK of our FIN (simultaneous close)
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 2,
          state.tcb.snd_nxt + 1,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, our_fin_ack)

      {:time_wait, _} = :sys.get_state(socket)

      Process.sleep(200)
      assert Process.alive?(socket)

      assert {:time_wait, %{unacked_segments: [], rto_timer_active: false}} =
               :sys.get_state(socket)
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 2,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
      socket = establish_connection(link, local_addr, remote_addr, mss: 48)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      # Send FIN from peer
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)

      {:close_wait, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Send large data that will be segmented
      payload = :binary.copy("x", 49)
      assert Tricep.send(socket, payload) == :ok

      # Should receive two segments
      assert_receive {:dummy_link_packet, _link, packet1}, 1000
      assert_receive {:dummy_link_packet, _link, packet2}, 1000

      <<_::binary-size(40), seg1::binary>> = packet1
      <<_::binary-size(40), seg2::binary>> = packet2

      parsed1 = Tcp.parse_segment(seg1)
      parsed2 = Tcp.parse_segment(seg2)

      assert byte_size(parsed1.payload) == 48
      assert byte_size(parsed2.payload) == 1
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 2,
          state.tcb.snd_nxt,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 2,
          close_wait_state.tcb.snd_nxt + 4,
          [:ack],
          65535
        )

      DummyLink.inject_packet(link, data_ack)

      # snd_una should be updated
      {:close_wait, updated_state} = :sys.get_state(socket)
      assert updated_state.tcb.snd_una == close_wait_state.tcb.snd_nxt + 4
      assert updated_state.tcb.snd_wnd == 65535
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          wrap_seq(state_before_ack.tcb.rcv_nxt - 1),
          state_before_ack.tcb.snd_nxt,
          [:ack],
          65_535
        )

      DummyLink.inject_packet(link, off_window_ack)

      assert_receive {:dummy_link_packet, _link, challenge_packet}, 1000
      <<_ip_header::binary-size(40), challenge_segment::binary>> = challenge_packet
      challenge = Tcp.parse_segment(challenge_segment)

      assert :ack in challenge.flags
      assert challenge.seq == state_before_ack.tcb.snd_nxt
      assert challenge.ack == state_before_ack.tcb.rcv_nxt

      {:close_wait, state_after_ack} = :sys.get_state(socket)

      assert state_after_ack.tcb.snd_una == state_before_ack.tcb.snd_una
      assert state_after_ack.tcb.snd_wnd == state_before_ack.tcb.snd_wnd
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 2,
          state.tcb.snd_nxt + 1,
          [:rst],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)
    end

    test "ACK of our FIN in LAST_ACK closes connection", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)
      on_exit(fn -> stop_socket(socket) end)
      Process.unlink(socket)

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      # Get state
      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      assert {:established, %{rto_ms: 100}} =
               :sys.replace_state(socket, fn
                 {:established, current_state} ->
                   {:established, %{current_state | rto_ms: 100}}
               end)

      # Send FIN from peer to get to CLOSE_WAIT
      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 2,
          last_ack_state.tcb.snd_nxt,
          [:ack],
          32768
        )

      DummyLink.inject_packet(link, our_fin_ack)

      {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)

      Process.sleep(200)
      assert Process.alive?(socket)
      assert {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 2,
          last_ack_state.tcb.snd_nxt - 1,
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
      syn = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      # Send RST response
      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          0,
          syn.seq + 1,
          [:rst, :ack],
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
          state.tcb.irs + 1,
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

      send(socket, {:icmpv6_error, {:packet_too_big, 1300}, %{seq: parsed1.seq, syn?: false}})

      wait_for_socket(socket, fn
        {:established, %{tcb: %{snd_mss: 1240}, unacked_segments: segments}} ->
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

      assert Tricep.send(socket, "x") == :ok
      assert_receive {:dummy_link_packet, _link, data_packet}, 1000
      <<_ip_header::binary-size(40), data_segment::binary>> = data_packet
      %{seq: sequence} = Tcp.parse_segment(data_segment)

      send(socket, {:icmpv6_error, {:packet_too_big, 1200}, %{seq: sequence, syn?: false}})

      wait_for_socket(socket, fn
        {:established, %{tcb: %{snd_mss: 1220}}} -> true
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

    test "data retransmission failure reports the retained soft ICMP error", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, window: 1)

      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.send(socket, "a") == :ok
      assert_receive {:dummy_link_packet, _link, data_packet}, 1000
      <<_ipv6_header::binary-size(40), data_segment::binary>> = data_packet
      %{seq: sequence} = Tcp.parse_segment(data_segment)

      send(socket, {:icmpv6_error, {:hard, :enetunreach}, %{seq: sequence, syn?: false}})

      wait_for_socket(socket, fn
        {:established, %{soft_error: :enetunreach}} -> true
        _state -> false
      end)

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

      assert Task.await(send_task, 1500) == {:error, :enetunreach}
      {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)
    end

    test "an advancing ACK clears the retained soft ICMP error", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr)

      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.send(socket, "Hello") == :ok
      assert_receive {:dummy_link_packet, _link, data_packet}, 1000
      <<_ipv6_header::binary-size(40), data_segment::binary>> = data_packet
      %{seq: sequence, payload: payload} = Tcp.parse_segment(data_segment)

      send(socket, {:icmpv6_error, {:hard, :enetunreach}, %{seq: sequence, syn?: false}})

      wait_for_socket(socket, fn
        {:established, %{soft_error: :enetunreach}} -> true
        _state -> false
      end)

      {:established, state} = :sys.get_state(socket)
      {{_, src_port}, _} = state.pair

      inject_ack(
        link,
        local_addr,
        remote_addr,
        src_port,
        state.tcb.rcv_nxt,
        sequence + byte_size(payload)
      )

      wait_for_socket(socket, fn
        {:established, %{soft_error: nil, tcb: %{snd_una: send_unacknowledged}}} ->
          send_unacknowledged == sequence + byte_size(payload)

        _state ->
          false
      end)
    end

    test "data retry exhaustion without a soft error reports timeout", %{
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
      assert {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)
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
        state_before_ack.tcb.rcv_nxt,
        state_before_ack.tcb.snd_una,
        12_345
      )

      {:established, state_after_ack} = :sys.get_state(socket)

      assert state_after_ack.tcb.snd_una == state_before_ack.tcb.snd_una
      assert state_after_ack.tcb.snd_nxt == state_before_ack.tcb.snd_nxt
      assert state_after_ack.unacked_segments == state_before_ack.unacked_segments
      assert state_after_ack.rto_timer_active == true
      assert state_after_ack.tcb.snd_wnd == 12_345
      refute_receive {:dummy_link_packet, _link, _packet}, 100
    end

    test "valid partial ACK advances snd_una and keeps later unacked segments", %{
      link: link,
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(link, local_addr, remote_addr, mss: 48)

      # Drain the ACK packet from handshake
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

      assert Tricep.send(socket, :binary.copy("x", 96)) == :ok

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
        state_before_ack.tcb.rcv_nxt,
        partial_ack,
        40_000
      )

      {:established, state_after_ack} = :sys.get_state(socket)

      assert state_after_ack.tcb.snd_una == partial_ack
      assert state_after_ack.tcb.snd_nxt == state_before_ack.tcb.snd_nxt
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
        state_before_ack.tcb.rcv_nxt,
        full_ack
      )

      {:established, state_after_ack} = :sys.get_state(socket)

      assert state_after_ack.tcb.snd_una == full_ack
      assert state_after_ack.tcb.snd_una == state_before_ack.tcb.snd_nxt
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
      invalid_ack = wrap_seq(state_before_ack.tcb.snd_nxt + 1)

      inject_ack(
        link,
        local_addr,
        remote_addr,
        src_port,
        state_before_ack.tcb.rcv_nxt,
        invalid_ack,
        1
      )

      assert_receive {:dummy_link_packet, _link, corrective_packet}, 1000
      <<_ip_header::binary-size(40), corrective_segment::binary>> = corrective_packet
      corrective = Tcp.parse_segment(corrective_segment)

      assert :ack in corrective.flags
      assert corrective.seq == state_before_ack.tcb.snd_nxt
      assert corrective.ack == state_before_ack.tcb.rcv_nxt

      {:established, state_after_ack} = :sys.get_state(socket)

      assert state_after_ack.tcb.snd_una == state_before_ack.tcb.snd_una
      assert state_after_ack.tcb.snd_nxt == state_before_ack.tcb.snd_nxt
      assert state_after_ack.tcb.snd_wnd == state_before_ack.tcb.snd_wnd
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
          state.tcb.irs + 1,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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

  # Preserve gen_statem's timer reference so the tests can inject the named
  # timeout event while the child is suspended, without racing the live RTO.
  defp start_passive_child_with_syn_ack_timer(link, local_addr, remote_addr) do
    :erlang.trace(self(), true, [:call, :set_on_spawn, {:tracer, self()}])

    :erlang.trace_pattern(
      {:erlang, :start_timer, 4},
      [{[:_, :_, :_, :_], [], [{:return_trace}]}],
      [:local]
    )

    try do
      passive = start_passive_child(link, local_addr, remote_addr)
      timer_ref = receive_syn_ack_timer_ref(passive.child)

      :ok = :sys.suspend(passive.child)

      :erlang.trace(passive.listener, false, [:call, :set_on_spawn])
      :erlang.trace(passive.child, false, [:call, :set_on_spawn])

      Map.put(passive, :syn_ack_timer_ref, timer_ref)
    after
      :erlang.trace(self(), false, [:call, :set_on_spawn])
      :erlang.trace_pattern({:erlang, :start_timer, 4}, false, [:local])
    end
  end

  defp receive_syn_ack_timer_ref(child) do
    receive do
      {:trace, ^child, :return_from, {:erlang, :start_timer, 4}, timer_ref} -> timer_ref
    after
      1_000 -> flunk("did not observe SYN-ACK RTO timer")
    end
  end

  defp exhaust_syn_ack_retries(child, timer_ref, event, quoted_tcp) do
    :sys.replace_state(child, fn {:syn_received, state} ->
      {:syn_received, %{state | syn_retransmit_count: 5}}
    end)

    :erlang.cancel_timer(timer_ref)
    send(child, {:icmpv6_error, event, quoted_tcp})
    send(child, {:timeout, timer_ref, {:timeout, :rto}})
    :ok = :sys.resume(child)
  end

  defp start_passive_child(link, local_addr, remote_addr, opts \\ []) do
    socket_opts = Keyword.get(opts, :socket_opts, %{})
    client_port = Keyword.get(opts, :client_port, 40_020)
    client_seq = Keyword.get(opts, :client_seq, 9_000)

    {:ok, listener} = Tricep.open(:inet6, :stream, :tcp, socket_opts)
    assert Tricep.bind(listener, %{family: :inet6, addr: @remote_addr_str, port: @port}) == :ok
    assert Tricep.listen(listener, 1) == :ok

    syn =
      Tcp.build_segment(
        {{local_addr, client_port}, {remote_addr, @port}},
        client_seq,
        0,
        [:syn],
        32_768
      )

    DummyLink.inject_packet(link, syn)

    assert_receive {:dummy_link_packet, ^link, syn_ack_packet}, 1000
    <<_::binary-size(40), syn_ack_segment::binary>> = syn_ack_packet
    syn_ack = Tcp.parse_segment(syn_ack_segment)

    assert {:listen, listen_state} = :sys.get_state(listener)
    [child] = Map.keys(listen_state.children)
    assert {:syn_received, state} = :sys.get_state(child)

    %{
      listener: listener,
      child: child,
      client_port: client_port,
      client_seq: client_seq,
      syn_ack: syn_ack,
      state: state
    }
  end

  defp queue_passive_child(link, local_addr, remote_addr, opts \\ []) do
    passive = start_passive_child(link, local_addr, remote_addr, opts)

    send_passive_ack(
      link,
      local_addr,
      remote_addr,
      passive.client_port,
      passive.client_seq,
      passive.syn_ack.seq
    )

    {:established, state} = wait_for_state_name(passive.child, :established, 1_000)
    assert_passive_child_queued(passive.listener, passive.child)

    %{passive | state: state}
  end

  defp queue_close_wait_passive_child(link, local_addr, remote_addr) do
    passive = start_passive_child(link, local_addr, remote_addr)

    fin =
      Tcp.build_segment(
        {{local_addr, passive.client_port}, {remote_addr, @port}},
        passive.state.tcb.rcv_nxt,
        passive.state.tcb.snd_nxt,
        [:ack, :fin],
        32_768
      )

    DummyLink.inject_packet(link, fin)
    assert_receive {:dummy_link_packet, ^link, _ack_packet}, 1_000

    {:close_wait, state} = wait_for_state_name(passive.child, :close_wait, 1_000)
    assert_passive_child_queued(passive.listener, passive.child)

    %{passive | state: state}
  end

  defp establish_passive_child_on_listener(listener, link, local_addr, remote_addr, client_port) do
    syn_ack = send_passive_syn(link, local_addr, remote_addr, client_port, 9_000 + client_port)
    pair = {{remote_addr, @port}, {local_addr, client_port}}
    child = Tricep.Application.lookup_socket_pair(pair)
    assert is_pid(child)

    send_passive_ack(link, local_addr, remote_addr, client_port, 9_000 + client_port, syn_ack.seq)
    {:established, state} = wait_for_state_name(child, :established, 1_000)

    %{
      listener: listener,
      child: child,
      client_port: client_port,
      client_seq: 9_000 + client_port,
      syn_ack: syn_ack,
      state: state
    }
  end

  defp passive_peer_reset(local_addr, remote_addr, passive) do
    Tcp.build_segment(
      {{local_addr, passive.client_port}, {remote_addr, @port}},
      passive.state.tcb.rcv_nxt,
      passive.state.tcb.snd_nxt,
      [:rst],
      0
    )
  end

  defp inject_passive_peer_reset(local_addr, remote_addr, passive) do
    reset = passive_peer_reset(local_addr, remote_addr, passive)
    :ok = Tricep.Socket.handle_packet(local_addr, remote_addr, reset)
  end

  defp assert_passive_child_queued(listener, child) do
    wait_for_socket(listener, fn
      {:listen, %{children: children, accept_queue: accept_queue}} ->
        match?(%Child{status: :queued}, Map.get(children, child)) and
          Enum.any?(accept_queue, &(&1.child == child))

      _state ->
        false
    end)
  end

  defp assert_passive_child_removed(listener, child) do
    wait_for_socket(listener, fn
      {:listen, %{children: children, accept_queue: accept_queue}} ->
        not Map.has_key?(children, child) and Enum.all?(accept_queue, &(&1.child != child))

      _state ->
        false
    end)
  end

  defp assert_passive_child_claimed(listener, child) do
    wait_for_socket(listener, fn
      {:listen, %{children: children, accept_queue: accept_queue}} ->
        match?(
          %Child{status: {:claimed, _id, _child_monitor, _caller_monitor}},
          Map.get(children, child)
        ) and
          Enum.any?(accept_queue, &(&1.child == child))

      _state ->
        false
    end)
  end

  # A passive child must be owned by exactly one of the listener and its
  # connection supervisor while it has not been handed to an accept caller.
  # Keeping this assertion close to the lifecycle tests catches stale queue
  # entries and detached-but-unclaimed children after each settlement path.
  defp assert_passive_ownership_invariant(listener) do
    {:listen, listener_state} = :sys.get_state(listener)
    supervisor = listener_state.connection_supervisor

    %{children: supervisor_children, handoffs: supervisor_handoffs} = :sys.get_state(supervisor)

    queued_children = Enum.map(listener_state.accept_queue, & &1.child)
    assert queued_children == Enum.uniq(queued_children)

    assert_ready_queue_has_no_parked_acceptors(listener_state, queued_children)

    assert_listener_children_owned(
      listener_state,
      supervisor,
      supervisor_children,
      supervisor_handoffs,
      queued_children
    )

    assert_supervisor_children_mirrored(listener_state, supervisor_children)

    expected_children = MapSet.new(Map.keys(listener_state.children))

    assert wait_until(fn ->
             MapSet.new(passive_registry_children(listener_state)) == expected_children
           end)

    :ok
  end

  defp assert_ready_queue_has_no_parked_acceptors(listener_state, queued_children) do
    if queued_children != [] do
      assert listener_state.accept_waiters == []
      assert listener_state.accept_selects == []
    end
  end

  defp assert_listener_children_owned(
         listener_state,
         supervisor,
         supervisor_children,
         supervisor_handoffs,
         queued_children
       ) do
    Enum.each(listener_state.children, fn {child, entry} ->
      assert Process.alive?(child)

      case entry.status do
        :pending ->
          assert Map.has_key?(supervisor_children, child)
          assert_passive_socket_owner(child, supervisor)

        :queued ->
          assert Map.has_key?(supervisor_children, child)
          assert child in queued_children
          assert_passive_socket_owner(child, supervisor)

        {:handoff, id} ->
          assert %{status: {:handoff, ^id}} = Map.fetch!(supervisor_children, child)
          assert Map.has_key?(supervisor_handoffs, id)
          refute child in queued_children
          assert_passive_socket_owner(child, supervisor)

        {:claimed, id, _child_monitor, _caller_monitor} ->
          assert %{status: {:claimed, ^id}} = Map.fetch!(supervisor_children, child)
          assert child in queued_children
          assert_passive_socket_owner(child, supervisor)
          assert {:established, %{passive_handoff: {:claimed, ^id}}} = :sys.get_state(child)
      end
    end)
  end

  defp assert_supervisor_children_mirrored(listener_state, supervisor_children) do
    Enum.each(supervisor_children, fn {child, entry} ->
      assert Map.has_key?(listener_state.children, child)

      case entry.status do
        :pending ->
          assert %{status: :pending} = Map.fetch!(listener_state.children, child)

        :queued ->
          assert %{status: :queued} = Map.fetch!(listener_state.children, child)

        {:handoff, id} ->
          assert %{status: {:handoff, ^id}} = Map.fetch!(listener_state.children, child)

        {:claimed, id} ->
          assert %{status: {:claimed, ^id, _child_monitor, _caller_monitor}} =
                   Map.fetch!(listener_state.children, child)
      end
    end)
  end

  defp assert_passive_socket_owner(child, owner) do
    assert {_state_name, %{passive_owner: ^owner, pair: pair}} = :sys.get_state(child)
    assert Tricep.Application.lookup_socket_pair(pair) == child
  end

  defp passive_registry_children(listener_state) do
    Registry.select(Tricep.SocketRegistry, [{{:"$1", :"$2", :_}, [], [{{:"$1", :"$2"}}]}])
    |> Enum.flat_map(fn
      {{{local_addr, local_port}, {_remote_addr, remote_port}}, child}
      when local_addr == listener_state.local_addr and
             local_port == listener_state.local_port and
             is_integer(remote_port) and is_pid(child) ->
        [child]

      _entry ->
        []
    end)
  end

  defp wait_for_listener_handoff(listener, child) do
    {:listen, %{connection_supervisor: connection_supervisor, handoffs: handoffs}} =
      wait_for_socket(listener, fn
        {:listen, %{handoffs: handoffs}} ->
          Enum.any?(handoffs, fn {_id, handoff} -> handoff.child == child end)

        _state ->
          false
      end)

    {id, _handoff} = Enum.find(handoffs, fn {_id, handoff} -> handoff.child == child end)
    {id, connection_supervisor}
  end

  defp wait_for_passive_handoff(listener, child) do
    {:listen, %{connection_supervisor: connection_supervisor, handoffs: handoffs}} =
      wait_for_socket(listener, fn
        {:listen, %{handoffs: handoffs}} ->
          Enum.any?(handoffs, fn {_id, handoff} -> handoff.child == child end)

        _state ->
          false
      end)

    {id, _handoff} = Enum.find(handoffs, fn {_id, handoff} -> handoff.child == child end)

    assert wait_until(fn ->
             case :sys.get_state(connection_supervisor) do
               %{handoffs: supervisor_handoffs} ->
                 match?(%{child: ^child}, Map.get(supervisor_handoffs, id))

               _state ->
                 false
             end
           end)

    {id, connection_supervisor}
  end

  defp assert_socket_message_queued(socket, message, timeout \\ 1_000) do
    assert wait_until(
             fn ->
               case Process.info(socket, :messages) do
                 {:messages, messages} -> message in messages
                 nil -> false
               end
             end,
             timeout
           )
  end

  defp prepend_stale_accepted_child(listener) do
    :sys.replace_state(listener, fn {:listen, state} ->
      accepted = %Accepted{child: self()}
      {:listen, %{state | accept_queue: [accepted | state.accept_queue]}}
    end)
  end

  defp passive_syn_event(local_addr, remote_addr, client_port) do
    {:passive_syn, local_addr, remote_addr, client_port, @port, <<>>}
  end

  defp start_passive_failure_supervisor(reason) do
    spawn(fn -> passive_failure_supervisor_loop(reason) end)
  end

  defp passive_failure_supervisor_loop(reason) do
    receive do
      {:"$gen_call", from, {:start_child, _opts}} ->
        GenServer.reply(from, {:error, reason})
        passive_failure_supervisor_loop(reason)
    end
  end

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
    server_seq = Keyword.get(opts, :server_seq, 5000)
    window = Keyword.get(opts, :window, 32768)

    segment_opts = Keyword.take(opts, [:mss, :window_scale])

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

  defp assert_callback_upgrade(socket) do
    assert :ok = :sys.suspend(socket)

    try do
      assert :ok = :sys.change_code(socket, Tricep.Socket, :old, [])
    after
      assert :ok = :sys.resume(socket)
    end

    assert {:status, ^socket, {:module, :gen_statem}, _status} = :sys.get_status(socket)
  end

  defp reconnect_socket(socket, link, local_addr, remote_addr, server_sequence) do
    task =
      Task.async(fn ->
        Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
      end)

    assert_receive {:dummy_link_packet, ^link, syn_packet}, 1000
    <<_::binary-size(40), syn_segment::binary>> = syn_packet
    syn = Tcp.parse_segment(syn_segment)
    <<src_port::16, _::binary>> = syn_segment

    syn_ack =
      Tcp.build_segment(
        {{local_addr, @port}, {remote_addr, src_port}},
        server_sequence,
        wrap_seq(syn.seq + 1),
        [:syn, :ack],
        32_768
      )

    DummyLink.inject_packet(link, syn_ack)
    assert Task.await(task, 1_000) == :ok
    assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1_000
  end

  defp descending_chunks(start, ending, chunk_size) do
    Stream.unfold(ending, fn
      cursor when cursor <= start ->
        nil

      cursor ->
        chunk_start = max(start, cursor - chunk_size)
        {{chunk_start, cursor}, chunk_start}
    end)
  end

  defp assert_challenge_ack(link, state) do
    assert_receive {:dummy_link_packet, ^link, packet}, 1_000
    <<_ip_header::binary-size(40), tcp_segment::binary>> = packet
    challenge_ack = Tcp.parse_segment(tcp_segment)

    assert challenge_ack.flags == [:ack]
    assert challenge_ack.seq == state.tcb.snd_nxt
    assert challenge_ack.ack == state.tcb.rcv_nxt
  end

  defp enter_time_wait(socket, link, local_addr, remote_addr, opts \\ []) do
    payload = Keyword.get(opts, :payload, <<>>)
    {:established, state} = :sys.get_state(socket)
    {{_, src_port}, _} = state.pair

    assert Tricep.close(socket) == :ok
    assert_receive {:dummy_link_packet, _link, _fin_packet}, 1000

    ack_segment =
      Tcp.build_segment(
        {{local_addr, @port}, {remote_addr, src_port}},
        state.tcb.irs + 1,
        state.tcb.snd_nxt + 1,
        [:ack],
        32768
      )

    DummyLink.inject_packet(link, ack_segment)
    assert {:fin_wait_2, _state} = :sys.get_state(socket)

    fin_segment =
      Tcp.build_segment(
        {{local_addr, @port}, {remote_addr, src_port}},
        state.tcb.irs + 1,
        state.tcb.snd_nxt + 1,
        [:fin, :ack],
        32768,
        payload: payload
      )

    DummyLink.inject_packet(link, fin_segment)

    assert {:time_wait, time_wait_state} = :sys.get_state(socket)
    assert_receive {:dummy_link_packet, ^link, fin_ack_packet}, 1000
    <<_::binary-size(40), fin_ack_segment::binary>> = fin_ack_packet
    fin_ack = Tcp.parse_segment(fin_ack_segment)

    assert fin_ack.flags == [:ack]
    assert fin_ack.ack == time_wait_state.tcb.rcv_nxt

    {state, time_wait_state}
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

    test "sends notification on SYN-ACK and normalizes zero MSS", %{
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
          32768,
          mss: 0
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      # Should receive select notification
      assert_receive {:"$socket", ^socket, :select, ^ref}, 1000

      # Drain ACK
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000
      assert {:established, %{tcb: %{snd_mss: 48}}} = :sys.get_state(socket)
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
          {{:syn_sent, :nowait},
           %{state | tcb: %{state.tcb | iss: 0xFFFFFFFF, snd_una: 0xFFFFFFFF, snd_nxt: 0}}}
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

      assert {:established, %{tcb: %{snd_una: 0, snd_nxt: 0, rcv_nxt: 5001}}} =
               :sys.get_state(socket)

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
    test "hard ICMPv6 failure notifies and returns its errno on retry", %{
      link: link
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      {:select, {:select_info, :connect, ref}} =
        Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port}, :nowait)

      assert_receive {:dummy_link_packet, ^link, syn_packet}, 1000
      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      %{seq: sequence} = Tcp.parse_segment(syn_segment)

      send(socket, {:icmpv6_error, {:hard, :eacces}, %{seq: sequence, syn?: true}})

      assert_receive {:"$socket", ^socket, :select, ^ref}, 1000
      assert {{:connect_failed, _selects, :eacces}, %{socket_opts: %{}}} = :sys.get_state(socket)

      # This response is handled only by Socket's root callback, so the retry
      # also proves the active-open callback switched to its destination owner.
      assert Tricep.connect(
               socket,
               %{family: :inet6, addr: @local_addr_str, port: @port},
               :nowait
             ) == {:error, :eacces}

      assert {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)
    end

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
      syn = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      # Send RST
      rst_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          0,
          syn.seq + 1,
          [:rst, :ack],
          0
        )

      DummyLink.inject_packet(link, rst_segment)

      assert_receive {:"$socket", ^socket, :select, ^ref}, 1000

      assert Tricep.connect(
               socket,
               %{family: :inet6, addr: @local_addr_str, port: @port},
               :nowait
             ) == {:error, :econnrefused}

      {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)
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

      {:closed, %{socket_opts: %{}}} = :sys.get_state(socket)
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
          state.tcb.irs + 1,
          wrap_seq(state.tcb.snd_nxt + byte_size(big_data)),
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
      assert probe.seq == wrap_seq(state.tcb.snd_nxt - 1)

      {:established, after_probe} = :sys.get_state(socket)
      assert after_probe.persist_timer_active
      assert after_probe.persist_timeout_ms == 2_000

      window_update =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
          [:ack],
          3
        )

      DummyLink.inject_packet(link, window_update)

      assert Task.await(send_task, 1000) == :ok

      assert_receive {:dummy_link_packet, _link, data_packet}, 1000
      <<_ip_header::binary-size(40), data_segment::binary>> = data_packet
      data = Tcp.parse_segment(data_segment)

      assert data.payload == "abc"
      assert data.seq == state.tcb.snd_nxt

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

  defp close_wait_after_in_order_fin_carried_ack(link, local_addr, remote_addr) do
    {socket, state, outbound} =
      established_with_unacknowledged_outbound(link, local_addr, remote_addr)

    {{_, src_port}, _} = state.pair

    fin_ack =
      Tcp.build_segment(
        {{local_addr, @port}, {remote_addr, src_port}},
        state.tcb.rcv_nxt,
        wrap_seq(outbound.seq + byte_size(outbound.payload)),
        [:ack, :fin],
        32_768
      )

    DummyLink.inject_packet(link, fin_ack)
    assert_receive {:dummy_link_packet, ^link, peer_fin_ack_packet}, 1000
    <<_::binary-size(40), peer_fin_ack_segment::binary>> = peer_fin_ack_packet
    peer_fin_ack = Tcp.parse_segment(peer_fin_ack_segment)

    assert peer_fin_ack.flags == [:ack]
    assert peer_fin_ack.seq == state.tcb.snd_nxt
    assert peer_fin_ack.ack == wrap_seq(state.tcb.rcv_nxt + 1)
    refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

    assert {:close_wait, close_wait_state} = :sys.get_state(socket)
    {socket, state, close_wait_state}
  end

  defp established_with_unacknowledged_outbound(link, local_addr, remote_addr) do
    socket = establish_connection(link, local_addr, remote_addr)
    on_exit(fn -> stop_socket(socket) end)
    assert_receive {:dummy_link_packet, ^link, _handshake_ack}, 1000

    assert Tricep.send(socket, "outbound") == :ok
    assert_receive {:dummy_link_packet, ^link, outbound_packet}, 1000
    <<_::binary-size(40), outbound_segment::binary>> = outbound_packet
    outbound = Tcp.parse_segment(outbound_segment)

    assert {:established, state} = :sys.get_state(socket)
    assert state.unacked_segments != []
    assert state.rto_timer_active
    {socket, state, outbound}
  end

  defp get_socket_src_port(socket) do
    {_state_name, state} = :sys.get_state(socket)
    {{_, src_port}, _} = state.pair
    src_port
  end

  defp get_socket_snd_nxt(socket) do
    {_state_name, state} = :sys.get_state(socket)
    state.tcb.snd_nxt
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
        state.tcb.irs + 1,
        state.tcb.snd_nxt + 1,
        [:ack],
        32768
      )

    DummyLink.inject_packet(link, ack_segment)

    {:fin_wait_2, _state} = :sys.get_state(socket)
    {state, src_port}
  end

  defp assert_ackless_payloads_preserve_receive_state(
         socket,
         link,
         local_addr,
         remote_addr,
         state_name,
         payloads
       ) do
    assert {^state_name, state} = :sys.get_state(socket)
    {{_, src_port}, _} = state.pair

    recv_task = Task.async(fn -> Tricep.recv(socket, 0, 5_000) end)
    wait_for_recv_waiters(socket)
    assert {:select, {:select_info, :recv, ref}} = Tricep.recv(socket, 0, :nowait)

    assert {^state_name, before_state} = :sys.get_state(socket)
    assert length(before_state.recv_waiters) == 1
    assert length(before_state.recv_selects) == 1

    Enum.each(payloads, fn {sequence, flags, payload} ->
      segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          sequence,
          before_state.tcb.snd_nxt,
          flags,
          0,
          payload: payload
        )

      DummyLink.inject_packet(link, segment)
      assert_receive {:dummy_link_packet, ^link, ack_packet}, 1000
      <<_::binary-size(40), ack_segment::binary>> = ack_packet
      ack = Tcp.parse_segment(ack_segment)

      assert ack.flags == [:ack]
      assert ack.payload == <<>>
      assert ack.seq == before_state.tcb.snd_nxt
      assert ack.ack == before_state.tcb.rcv_nxt
      assert ack.window == before_state.tcb.rcv_adv_wnd
    end)

    refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100
    refute_receive {:"$socket", ^socket, :select, ^ref}, 100
    assert Task.yield(recv_task, 50) == nil

    assert {^state_name, after_state} = :sys.get_state(socket)
    assert after_state.tcb.rcv_nxt == before_state.tcb.rcv_nxt
    assert after_state.recv_buffer == before_state.recv_buffer
    assert after_state.out_of_order_segments == before_state.out_of_order_segments
    assert after_state.out_of_order_fin == before_state.out_of_order_fin
    assert after_state.fin_received == before_state.fin_received
    assert after_state.recv_waiters == before_state.recv_waiters
    assert after_state.recv_selects == before_state.recv_selects
    assert after_state.tcb.snd_wnd == 0
    assert after_state.tcb.snd_una == before_state.tcb.snd_una
    assert after_state.tcb.snd_nxt == before_state.tcb.snd_nxt
    refute after_state.persist_timer_active

    Task.shutdown(recv_task, :brutal_kill)
  end

  defp assert_ackless_out_of_order_fin_does_not_close(
         socket,
         link,
         local_addr,
         remote_addr,
         state_name
       ) do
    assert {^state_name, state} = :sys.get_state(socket)
    {{_, src_port}, _} = state.pair

    out_of_order_fin =
      Tcp.build_segment(
        {{local_addr, @port}, {remote_addr, src_port}},
        wrap_seq(state.tcb.rcv_nxt + 10),
        state.tcb.snd_nxt,
        [:fin],
        0
      )

    DummyLink.inject_packet(link, out_of_order_fin)
    assert_receive {:dummy_link_packet, ^link, fin_ack_packet}, 1000
    <<_::binary-size(40), fin_ack_segment::binary>> = fin_ack_packet
    fin_ack = Tcp.parse_segment(fin_ack_segment)

    assert fin_ack.flags == [:ack]
    assert fin_ack.payload == <<>>
    assert fin_ack.seq == state.tcb.snd_nxt
    assert fin_ack.ack == state.tcb.rcv_nxt
    assert fin_ack.window == state.tcb.rcv_adv_wnd
    refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

    assert {^state_name, fin_state} = :sys.get_state(socket)
    assert fin_state.tcb.rcv_nxt == state.tcb.rcv_nxt
    assert fin_state.recv_buffer == <<>>
    assert fin_state.out_of_order_segments == []
    assert fin_state.out_of_order_fin == nil
    refute fin_state.fin_received
    assert fin_state.tcb.snd_wnd == 0

    out_of_order_payload_fin =
      Tcp.build_segment(
        {{local_addr, @port}, {remote_addr, src_port}},
        wrap_seq(state.tcb.rcv_nxt + 5),
        state.tcb.snd_nxt,
        [:psh, :fin],
        0,
        payload: "world"
      )

    DummyLink.inject_packet(link, out_of_order_payload_fin)
    assert_receive {:dummy_link_packet, ^link, payload_ack_packet}, 1000
    <<_::binary-size(40), payload_ack_segment::binary>> = payload_ack_packet
    payload_ack = Tcp.parse_segment(payload_ack_segment)

    assert payload_ack.flags == [:ack]
    assert payload_ack.payload == <<>>
    assert payload_ack.seq == state.tcb.snd_nxt
    assert payload_ack.ack == state.tcb.rcv_nxt
    refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

    assert {^state_name, queued_state} = :sys.get_state(socket)

    assert queued_state.out_of_order_segments == [
             {wrap_seq(state.tcb.rcv_nxt + 5), wrap_seq(state.tcb.rcv_nxt + 10), "world"}
           ]

    assert queued_state.out_of_order_fin == nil
    refute queued_state.fin_received

    gap_fill =
      Tcp.build_segment(
        {{local_addr, @port}, {remote_addr, src_port}},
        state.tcb.rcv_nxt,
        state.tcb.snd_nxt,
        [:ack, :psh],
        32_768,
        payload: "hello"
      )

    DummyLink.inject_packet(link, gap_fill)
    assert_receive {:dummy_link_packet, ^link, data_ack_packet}, 1000
    <<_::binary-size(40), data_ack_segment::binary>> = data_ack_packet
    data_ack = Tcp.parse_segment(data_ack_segment)

    assert data_ack.flags == [:ack]
    assert data_ack.seq == state.tcb.snd_nxt
    assert data_ack.ack == wrap_seq(state.tcb.rcv_nxt + 10)
    refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

    assert {^state_name, after_state} = :sys.get_state(socket)
    assert after_state.recv_buffer == "helloworld"
    assert after_state.out_of_order_fin == nil
    refute after_state.fin_received
  end

  defp assert_ackless_future_payload_invalidates_advisory_fin(
         socket,
         link,
         local_addr,
         remote_addr,
         state_name
       ) do
    assert {^state_name, state} = :sys.get_state(socket)
    {{_, src_port}, _} = state.pair

    recv_task = Task.async(fn -> Tricep.recv(socket, 0, 5_000) end)
    wait_for_recv_waiters(socket)
    assert {:select, {:select_info, :recv, ref}} = Tricep.recv(socket, 0, :nowait)

    queued_fin =
      Tcp.build_segment(
        {{local_addr, @port}, {remote_addr, src_port}},
        wrap_seq(state.tcb.rcv_nxt + 5),
        state.tcb.snd_nxt,
        [:ack, :psh, :fin],
        32_768,
        payload: "world"
      )

    DummyLink.inject_packet(link, queued_fin)
    assert_receive {:dummy_link_packet, ^link, queued_fin_ack_packet}, 1000
    <<_::binary-size(40), queued_fin_ack_segment::binary>> = queued_fin_ack_packet
    queued_fin_ack = Tcp.parse_segment(queued_fin_ack_segment)

    assert queued_fin_ack.flags == [:ack]
    assert queued_fin_ack.payload == <<>>
    assert queued_fin_ack.seq == state.tcb.snd_nxt
    assert queued_fin_ack.ack == state.tcb.rcv_nxt
    assert queued_fin_ack.window == state.tcb.rcv_adv_wnd - 5
    refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

    assert {^state_name, pending_state} = :sys.get_state(socket)

    assert pending_state.out_of_order_segments == [
             {wrap_seq(state.tcb.rcv_nxt + 5), wrap_seq(state.tcb.rcv_nxt + 10), "world"}
           ]

    assert pending_state.out_of_order_fin == wrap_seq(state.tcb.rcv_nxt + 10)

    ackless_payload =
      Tcp.build_segment(
        {{local_addr, @port}, {remote_addr, src_port}},
        wrap_seq(state.tcb.rcv_nxt + 10),
        state.tcb.snd_nxt,
        [:psh],
        0,
        payload: "WXYZ"
      )

    DummyLink.inject_packet(link, ackless_payload)
    assert_receive {:dummy_link_packet, ^link, ackless_ack_packet}, 1000
    <<_::binary-size(40), ackless_ack_segment::binary>> = ackless_ack_packet
    ackless_ack = Tcp.parse_segment(ackless_ack_segment)

    assert ackless_ack.flags == [:ack]
    assert ackless_ack.payload == <<>>
    assert ackless_ack.seq == state.tcb.snd_nxt
    assert ackless_ack.ack == state.tcb.rcv_nxt
    assert ackless_ack.window == state.tcb.rcv_adv_wnd - 9
    refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100
    refute_receive {:"$socket", ^socket, :select, ^ref}, 100
    assert Task.yield(recv_task, 50) == nil

    assert {^state_name, attacked_state} = :sys.get_state(socket)
    assert attacked_state.tcb.rcv_nxt == state.tcb.rcv_nxt
    assert attacked_state.recv_buffer == <<>>

    assert attacked_state.out_of_order_segments == [
             {wrap_seq(state.tcb.rcv_nxt + 5), wrap_seq(state.tcb.rcv_nxt + 10), "world"},
             {wrap_seq(state.tcb.rcv_nxt + 10), wrap_seq(state.tcb.rcv_nxt + 14), "WXYZ"}
           ]

    assert attacked_state.out_of_order_fin == nil
    assert attacked_state.tcb.snd_wnd == 0

    gap_fill =
      Tcp.build_segment(
        {{local_addr, @port}, {remote_addr, src_port}},
        state.tcb.rcv_nxt,
        state.tcb.snd_nxt,
        [:ack, :psh],
        32_768,
        payload: "hello"
      )

    DummyLink.inject_packet(link, gap_fill)
    assert_receive {:dummy_link_packet, ^link, fin_ack_packet}, 1000
    <<_::binary-size(40), fin_ack_segment::binary>> = fin_ack_packet
    fin_ack = Tcp.parse_segment(fin_ack_segment)

    assert fin_ack.flags == [:ack]
    assert fin_ack.payload == <<>>
    assert fin_ack.seq == state.tcb.snd_nxt
    assert fin_ack.ack == wrap_seq(state.tcb.rcv_nxt + 14)
    assert fin_ack.window == state.tcb.rcv_adv_wnd
    refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100
    assert_receive {:"$socket", ^socket, :select, ^ref}, 1000
    assert Task.await(recv_task, 1000) == {:ok, "helloworldWXYZ"}

    assert {^state_name, streamed_state} = :sys.get_state(socket)
    assert streamed_state.out_of_order_segments == []
    assert streamed_state.out_of_order_fin == nil
    refute streamed_state.fin_received

    genuine_fin =
      Tcp.build_segment(
        {{local_addr, @port}, {remote_addr, src_port}},
        streamed_state.tcb.rcv_nxt,
        state.tcb.snd_nxt,
        [:ack, :fin],
        32_768
      )

    DummyLink.inject_packet(link, genuine_fin)
    assert_receive {:dummy_link_packet, ^link, genuine_fin_ack_packet}, 1000
    <<_::binary-size(40), genuine_fin_ack_segment::binary>> = genuine_fin_ack_packet
    genuine_fin_ack = Tcp.parse_segment(genuine_fin_ack_segment)

    assert genuine_fin_ack.flags == [:ack]
    assert genuine_fin_ack.payload == <<>>
    assert genuine_fin_ack.seq == state.tcb.snd_nxt
    assert genuine_fin_ack.ack == wrap_seq(state.tcb.rcv_nxt + 15)
    assert genuine_fin_ack.window == state.tcb.rcv_adv_wnd
    refute_receive {:dummy_link_packet, ^link, _unexpected_packet}, 100

    expected_state = if state_name == :established, do: :close_wait, else: :time_wait
    assert {^expected_state, final_state} = :sys.get_state(socket)
    assert final_state.fin_received
    assert Tricep.recv(socket, 0, 1000) == {:ok, <<>>}
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

  defp wait_until(predicate, timeout \\ 1_000)

  defp wait_until(predicate, timeout) when is_integer(timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    wait_until_deadline(predicate, deadline)
  end

  defp wait_until_deadline(predicate, deadline) do
    if predicate.() do
      true
    else
      if System.monotonic_time(:millisecond) >= deadline do
        false
      else
        Process.sleep(1)
        wait_until_deadline(predicate, deadline)
      end
    end
  end

  defp send_passive_syn(link, local_addr, remote_addr, client_port, client_seq, mss \\ 1000)
       when is_pid(link) do
    syn =
      Tcp.build_segment(
        {{local_addr, client_port}, {remote_addr, @port}},
        client_seq,
        0,
        [:syn],
        32768,
        mss: mss
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
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
          state.tcb.irs + 1,
          state.tcb.snd_nxt + 1,
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
      socket = establish_connection(link, local_addr, remote_addr, mss: 48, window: 1)

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
          state.tcb.irs + 1,
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
          state.tcb.irs + 1,
          state.tcb.iss + 1,
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
          state.tcb.irs + 1,
          state.tcb.iss + 1,
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
