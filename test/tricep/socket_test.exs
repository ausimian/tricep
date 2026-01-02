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
end
