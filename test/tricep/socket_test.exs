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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: server_seq,
          ack: syn_parsed.seq + 1,
          flags: [:syn, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: 0,
          ack: 0,
          flags: [:rst],
          window: 0
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: 5000,
          ack: syn_parsed.seq + 999,
          flags: [:ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: 5000,
          ack: syn_parsed.seq + 1,
          flags: [:syn, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: 5000,
          ack: syn_parsed.seq + 1,
          flags: [:syn, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: 1000,
          ack: 0,
          flags: [:syn],
          window: 32768
        )

      DummyLink.inject_packet(link, syn_only)

      # Give it time to process
      Process.sleep(50)

      # Socket should still be waiting - send proper SYN-ACK
      syn_ack_segment =
        Tcp.build_segment(
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: 5000,
          ack: syn_parsed.seq + 1,
          flags: [:syn, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: 5000,
          ack: syn_parsed.seq + 1,
          flags: [:syn, :ack],
          window: 32768
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
      assert parsed.options.mss == 1220

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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: 5000,
          ack: syn_parsed.seq + 1,
          flags: [:syn, :ack],
          window: 32768,
          mss: peer_mss
        )

      DummyLink.inject_packet(link, syn_ack_segment)

      assert Task.await(task, 1000) == :ok

      # Check that the socket stored the peer's MSS
      # gen_statem returns {state_name, state_data}
      {:established, state} = :sys.get_state(socket)
      assert state.snd_mss == peer_mss
      assert state.rcv_mss == 1220
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: 5000,
          ack: syn_parsed.seq + 1,
          flags: [:syn, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:ack, :psh],
          window: 32768,
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:ack, :psh],
          window: 32768,
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:ack, :psh],
          window: 32768,
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1 + 10,
          ack: state.snd_nxt,
          flags: [:ack, :psh],
          window: 32768,
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:ack, :psh],
          window: 32768,
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:ack, :psh],
          window: 32768,
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:rst],
          window: 0
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:ack],
          window: new_window
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1000,
          ack: state.snd_nxt,
          flags: [:ack, :psh],
          window: 32768,
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:ack, :psh],
          window: 32768,
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:ack],
          window: 32768
        )

      DummyLink.inject_packet(link, ack_segment)
      Process.sleep(50)

      # Should be in FIN_WAIT_2
      {:fin_wait_2, _} = :sys.get_state(socket)

      # Send FIN from peer
      fin_segment =
        Tcp.build_segment(
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768,
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

      # send should fail
      assert Tricep.send(socket, "data") == {:error, :enotconn}
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:rst],
          window: 0
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:ack],
          window: 32768
        )

      DummyLink.inject_packet(link, ack_segment)
      Process.sleep(50)

      {:fin_wait_2, _} = :sys.get_state(socket)

      # Send RST
      rst_segment =
        Tcp.build_segment(
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:rst],
          window: 0
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:ack],
          window: 32768
        )

      DummyLink.inject_packet(link, ack_segment)
      Process.sleep(50)

      {:fin_wait_2, _} = :sys.get_state(socket)

      # Send data (half-close allows peer to still send)
      data_segment =
        Tcp.build_segment(
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:ack, :psh],
          window: 32768,
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:ack],
          window: 32768
        )

      DummyLink.inject_packet(link, ack_segment)
      Process.sleep(50)

      {:fin_wait_2, _} = :sys.get_state(socket)

      # Send segment with wrong seq (out of order)
      wrong_seq =
        Tcp.build_segment(
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1000,
          ack: state.snd_nxt + 1,
          flags: [:ack, :psh],
          window: 32768,
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:ack],
          window: 32768
        )

      DummyLink.inject_packet(link, ack_segment)
      Process.sleep(50)

      {:fin_wait_2, _} = :sys.get_state(socket)

      # Send FIN from peer
      fin_segment =
        Tcp.build_segment(
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:ack],
          window: 32768
        )

      DummyLink.inject_packet(link, ack_segment)
      Process.sleep(50)

      # Send FIN from peer
      fin_segment =
        Tcp.build_segment(
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:ack],
          window: 32768
        )

      DummyLink.inject_packet(link, ack_segment)
      Process.sleep(50)

      fin_segment =
        Tcp.build_segment(
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt + 1,
          flags: [:fin, :ack],
          window: 32768
        )

      DummyLink.inject_packet(link, fin_segment)
      Process.sleep(50)

      {:time_wait, _} = :sys.get_state(socket)

      # Drain first ACK
      assert_receive {:dummy_link_packet, _link, _first_ack}, 1000

      # Send non-FIN segment (just ACK)
      just_ack =
        Tcp.build_segment(
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 2,
          ack: state.snd_nxt + 1,
          flags: [:ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
        )

      DummyLink.inject_packet(link, fin_segment)
      Process.sleep(50)

      {:closing, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _their_fin_ack}, 1000

      # Send RST
      rst_segment =
        Tcp.build_segment(
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 2,
          ack: state.snd_nxt + 1,
          flags: [:rst],
          window: 0
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
        )

      DummyLink.inject_packet(link, fin_segment)
      Process.sleep(50)

      {:closing, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _their_fin_ack}, 1000

      # Now send ACK of our FIN
      our_fin_ack =
        Tcp.build_segment(
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 2,
          ack: state.snd_nxt + 1,
          flags: [:ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
        )

      DummyLink.inject_packet(link, fin_segment)
      Process.sleep(50)

      {:closing, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _their_fin_ack}, 1000

      # Send ACK with wrong ack number
      wrong_ack =
        Tcp.build_segment(
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 2,
          ack: state.snd_nxt,
          flags: [:ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
        )

      DummyLink.inject_packet(link, fin_segment)
      Process.sleep(50)

      {:close_wait, _} = :sys.get_state(socket)

      # Drain ACK for their FIN
      assert_receive {:dummy_link_packet, _link, _fin_ack}, 1000

      # Send RST
      rst_segment =
        Tcp.build_segment(
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 2,
          ack: state.snd_nxt,
          flags: [:rst],
          window: 0
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 2,
          ack: close_wait_state.snd_nxt + 4,
          flags: [:ack],
          window: 65535
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 2,
          ack: state.snd_nxt + 1,
          flags: [:rst],
          window: 0
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 2,
          ack: last_ack_state.snd_nxt,
          flags: [:ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 1,
          ack: state.snd_nxt,
          flags: [:fin, :ack],
          window: 32768
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
          src_addr: local_addr,
          dst_addr: remote_addr,
          src_port: @port,
          dst_port: src_port,
          seq: state.irs + 2,
          ack: last_ack_state.snd_nxt - 1,
          flags: [:ack],
          window: 32768
        )

      DummyLink.inject_packet(link, wrong_ack)
      Process.sleep(50)

      # Should still be in LAST_ACK (wrong ACK ignored)
      {:last_ack, _} = :sys.get_state(socket)
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

    syn_ack_opts = [
      src_addr: local_addr,
      dst_addr: remote_addr,
      src_port: @port,
      dst_port: src_port,
      seq: server_seq,
      ack: syn_parsed.seq + 1,
      flags: [:syn, :ack],
      window: 32768
    ]

    syn_ack_opts = if mss, do: Keyword.put(syn_ack_opts, :mss, mss), else: syn_ack_opts
    syn_ack_segment = Tcp.build_segment(syn_ack_opts)

    DummyLink.inject_packet(link, syn_ack_segment)

    assert Task.await(task, 1000) == :ok

    socket
  end
end
