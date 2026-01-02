defmodule Tricep.Integration.TcpHandshakeTest do
  @moduledoc """
  Integration tests for TCP handshake with real TUN device and kernel sockets.

  These tests require root privileges or CAP_NET_ADMIN capability.
  Run with: mix test --include integration
  """

  use Tricep.IntegrationCase

  @ifaddr {0xFD00, 0, 0, 0, 0, 0, 0, 0x21}
  @ifaddr_str "fd00::21"
  @dstaddr_str "fd00::22"

  setup do
    link = create_test_link(ifaddr: @ifaddr_str, dstaddr: @dstaddr_str)

    on_exit(fn ->
      Tricep.Link.drop(link)
    end)

    %{link: link}
  end

  describe "TCP three-way handshake" do
    test "completes handshake with kernel TCP listener", %{link: _link} do
      # Start a kernel TCP listener on the interface address
      {:ok, listen_sock} = create_kernel_listener(@ifaddr, 44444)

      # Start an async task to accept the connection
      accept_task =
        Task.async(fn ->
          accept_connection(listen_sock, 10_000)
        end)

      # Give listener time to start
      Process.sleep(50)

      # Open a Tricep socket and connect
      {:ok, sock} = Tricep.open(:inet6, :stream, :tcp)
      address = %{family: :inet6, addr: @ifaddr, port: 44444}

      # This should complete the three-way handshake
      result = Tricep.connect(sock, address)

      assert result == :ok

      # The listener should have accepted the connection
      {:ok, client_sock} = Task.await(accept_task, 5_000)

      # Cleanup
      :socket.close(client_sock)
      :socket.close(listen_sock)
    end

    test "returns error when connection is refused", %{link: _link} do
      # Open a Tricep socket and try to connect to a port with no listener
      {:ok, sock} = Tricep.open(:inet6, :stream, :tcp)
      address = %{family: :inet6, addr: @ifaddr, port: 55555}

      # This should fail with connection refused (RST received)
      result = Tricep.connect(sock, address)

      assert result == {:error, :econnrefused}
    end

    test "returns error for unreachable destination", %{link: _link} do
      # Try to connect to an address not covered by the TUN link
      {:ok, sock} = Tricep.open(:inet6, :stream, :tcp)
      address = %{family: :inet6, addr: {0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1}, port: 80}

      result = Tricep.connect(sock, address)

      assert result == {:error, :enetunreach}
    end
  end

  describe "multiple connections" do
    test "can establish multiple simultaneous connections", %{link: _link} do
      # Start listeners on different ports
      {:ok, listen_sock1} = create_kernel_listener(@ifaddr, 44001)
      {:ok, listen_sock2} = create_kernel_listener(@ifaddr, 44002)

      # Start accept tasks
      accept1 = Task.async(fn -> accept_connection(listen_sock1, 10_000) end)
      accept2 = Task.async(fn -> accept_connection(listen_sock2, 10_000) end)

      Process.sleep(50)

      # Open two Tricep sockets and connect
      {:ok, sock1} = Tricep.open(:inet6, :stream, :tcp)
      {:ok, sock2} = Tricep.open(:inet6, :stream, :tcp)

      addr1 = %{family: :inet6, addr: @ifaddr, port: 44001}
      addr2 = %{family: :inet6, addr: @ifaddr, port: 44002}

      assert Tricep.connect(sock1, addr1) == :ok
      assert Tricep.connect(sock2, addr2) == :ok

      # Both should have been accepted
      {:ok, client1} = Task.await(accept1, 5_000)
      {:ok, client2} = Task.await(accept2, 5_000)

      # Cleanup
      :socket.close(client1)
      :socket.close(client2)
      :socket.close(listen_sock1)
      :socket.close(listen_sock2)
    end
  end
end
