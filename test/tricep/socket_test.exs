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

    on_exit(fn ->
      if Process.alive?(link), do: GenServer.stop(link)
    end)

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
      assert :syn in parsed.flags
      refute :ack in parsed.flags
      assert parsed.ack == 0

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

      assert {:error, _} = result
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

      # Give it time to process
      Process.sleep(50)

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

      # Give it time to process
      Process.sleep(50)

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

      # Give it time to block
      Process.sleep(50)

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

      # Give it time to block
      Process.sleep(50)

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
      Process.sleep(50)
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

      # Wait for it to be processed
      Process.sleep(50)

      # Drain the ACK
      assert_receive {:dummy_link_packet, _link, _ack}, 1000

      # Now recv should return immediately (data already buffered)
      assert Tricep.recv(socket, 0, 1000) == {:ok, "Pre-buffered data"}
    end

    test "recv timeout that fires after data arrives is ignored", %{
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

      # Give it time to register waiter
      Process.sleep(20)

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

      # Wait past the original timeout - no crash should occur
      # (the timeout fires but waiter is already gone)
      Process.sleep(600)

      # Socket should still be usable
      {:established, _} = :sys.get_state(socket)
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

      # Give it time to block
      Process.sleep(50)

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

      # Give time to process
      Process.sleep(50)

      # Check window was updated
      {:established, new_state} = :sys.get_state(socket)
      assert new_state.snd_wnd == new_window
      assert new_state.snd_wnd != initial_snd_wnd or initial_snd_wnd == new_window
    end

    test "ignores out of order packets", %{
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

      # Inject packet with wrong sequence number (too high)
      wrong_seq_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1000,
          state.snd_nxt,
          [:ack, :psh],
          32768,
          payload: "Out of order"
        )

      DummyLink.inject_packet(link, wrong_seq_segment)

      # Give time to process
      Process.sleep(50)

      # Recv should timeout since data was ignored
      result = Tricep.recv(socket, 0, 100)
      assert result == {:error, :timeout}

      # rcv_nxt should not have changed
      {:established, new_state} = :sys.get_state(socket)
      assert new_state.rcv_nxt == state.rcv_nxt
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

      # Give time to process
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

      # Should be in CLOSE_WAIT
      {:close_wait, _} = :sys.get_state(socket)

      # Should receive ACK for FIN
      assert_receive {:dummy_link_packet, _link, _ack_packet2}, 1000

      # recv should return EOF
      assert Tricep.recv(socket, 0, 100) == {:ok, <<>>}
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
      Process.sleep(50)

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

      # Give it time to block
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

      # Should still be in FIN_WAIT_1 (wrong ACK ignored)
      {:fin_wait_1, _} = :sys.get_state(socket)
    end
  end

  describe "FIN_WAIT_2 state" do
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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

      {:fin_wait_2, _} = :sys.get_state(socket)

      # Inject malformed segment
      DummyLink.inject_packet(link, <<1, 2, 3>>)
      Process.sleep(50)

      # Should still be in FIN_WAIT_2
      {:fin_wait_2, _} = :sys.get_state(socket)
    end

    test "ignores unexpected segment in FIN_WAIT_2", %{
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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

      {:time_wait, _} = :sys.get_state(socket)

      # Drain ACK for peer's FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Wait for TIME_WAIT to expire (2 seconds + buffer)
      Process.sleep(2100)

      {:closed, nil} = :sys.get_state(socket)
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
      Process.sleep(50)

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
      Process.sleep(50)

      {:time_wait, _} = :sys.get_state(socket)

      # Drain first ACK
      assert_receive {:dummy_link_packet, _link, _first_ack}, 1000

      # Send FIN again (simulating retransmit because peer didn't get our ACK)
      DummyLink.inject_packet(link, fin_segment)
      Process.sleep(50)

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
      Process.sleep(50)

      fin_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          state.irs + 1,
          state.snd_nxt + 1,
          [:fin, :ack],
          32768
        )

      DummyLink.inject_packet(link, fin_segment)
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

      {:closing, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _their_fin_ack}, 1000

      # Inject malformed segment
      DummyLink.inject_packet(link, <<1, 2, 3>>)
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

      # snd_una should be updated
      {:close_wait, updated_state} = :sys.get_state(socket)
      assert updated_state.snd_una == close_wait_state.snd_nxt + 4
      assert updated_state.snd_wnd == 65535
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
      Process.sleep(50)

      {:close_wait, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Inject malformed segment
      DummyLink.inject_packet(link, <<1, 2, 3>>)
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

      {:closed, nil} = :sys.get_state(socket)
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
      Process.sleep(50)

      {:close_wait, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Close to get to LAST_ACK
      assert Tricep.close(socket) == :ok
      assert_receive {:dummy_link_packet, _link, _our_fin}, 1000

      {:last_ack, _} = :sys.get_state(socket)

      # Inject malformed segment
      DummyLink.inject_packet(link, <<1, 2, 3>>)
      Process.sleep(50)

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
      Process.sleep(50)

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
      Process.sleep(50)

      # Should still be in LAST_ACK (wrong ACK ignored)
      {:last_ack, _} = :sys.get_state(socket)
    end
  end

  describe "SYN retransmission" do
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

      # Wait for connection to fail (after 6th timeout at 32s)
      Process.sleep(35_000)

      # Socket should be closed now
      {:closed, nil} = :sys.get_state(socket)
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
      Process.sleep(50)

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
      Process.sleep(50)

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

    # Build SYN-ACK with optional MSS
    server_seq = 5000
    mss = Keyword.get(opts, :mss)

    segment_opts = if mss, do: [mss: mss], else: []

    syn_ack_segment =
      Tcp.build_segment(
        {{local_addr, @port}, {remote_addr, src_port}},
        server_seq,
        syn_parsed.seq + 1,
        [:syn, :ack],
        32768,
        segment_opts
      )

    DummyLink.inject_packet(link, syn_ack_segment)

    assert Task.await(task, 1000) == :ok

    socket
  end

  # --- Timeout and :nowait tests ---

  describe "connect with :nowait" do
    test "returns select tuple immediately", %{remote_addr: remote_addr} do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      result = Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port}, :nowait)

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

      # Now connect should return :eisconn (already connected)
      assert Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port}, :nowait) ==
               {:error, :eisconn}
    end
  end

  describe "connect with timeout" do
    test "returns {:error, :timeout} when no SYN-ACK received", %{remote_addr: remote_addr} do
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

      # Give time for data to be processed
      Process.sleep(50)

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

  # Helper functions for timeout tests
  defp get_socket_src_port(socket) do
    {_state_name, state} = :sys.get_state(socket)
    {{_, src_port}, _} = state.pair
    src_port
  end

  defp get_socket_snd_nxt(socket) do
    {_state_name, state} = :sys.get_state(socket)
    state.snd_nxt
  end

  defp wrap_seq(n), do: Bitwise.band(n, 0xFFFFFFFF)
end
