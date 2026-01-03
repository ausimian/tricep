defmodule Tricep.DataTransferIntegrationTest do
  use Tricep.IntegrationCase, async: false

  setup do
    # Use shared TUN from test_helper.exs
    ExUnit.configuration()[:tricep]
  end

  describe "send/2 integration" do
    test "sends data to kernel socket", ctx do
      # Create kernel listener
      {:ok, listen_sock, port} = create_kernel_listener(ctx.ifaddr)

      on_exit(fn -> :socket.close(listen_sock) end)

      # Create Tricep socket and connect
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      # Start connect in background
      connect_task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: ctx.ifaddr_str, port: port})
        end)

      # Accept the connection on kernel side
      {:ok, client_sock} = accept_connection(listen_sock)

      on_exit(fn -> :socket.close(client_sock) end)

      # Wait for connect to complete
      assert Task.await(connect_task, 5000) == :ok

      # Send data through Tricep
      assert Tricep.send(socket, "Hello from Tricep!") == :ok

      # Receive on kernel socket
      {:ok, data} = :socket.recv(client_sock, 0, 5000)
      assert data == "Hello from Tricep!"
    end

    test "sends large data split into segments", ctx do
      {:ok, listen_sock, port} = create_kernel_listener(ctx.ifaddr)

      on_exit(fn -> :socket.close(listen_sock) end)

      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      connect_task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: ctx.ifaddr_str, port: port})
        end)

      {:ok, client_sock} = accept_connection(listen_sock)

      on_exit(fn -> :socket.close(client_sock) end)

      assert Task.await(connect_task, 5000) == :ok

      # Send data larger than MSS (1220 bytes for IPv6)
      large_data = :crypto.strong_rand_bytes(5000)
      assert Tricep.send(socket, large_data) == :ok

      # Receive all data on kernel socket (may come in multiple recv calls)
      received = recv_all(client_sock, byte_size(large_data), 5000)
      assert received == large_data
    end
  end

  describe "recv/2 integration" do
    test "receives data from kernel socket", ctx do
      {:ok, listen_sock, port} = create_kernel_listener(ctx.ifaddr)

      on_exit(fn -> :socket.close(listen_sock) end)

      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      connect_task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: ctx.ifaddr_str, port: port})
        end)

      {:ok, client_sock} = accept_connection(listen_sock)

      on_exit(fn -> :socket.close(client_sock) end)

      assert Task.await(connect_task, 5000) == :ok

      # Send data from kernel socket
      :ok = :socket.send(client_sock, "Hello from kernel!")

      # Receive on Tricep socket
      assert Tricep.recv(socket, 0, 5000) == {:ok, "Hello from kernel!"}
    end

    test "receives multiple messages", ctx do
      {:ok, listen_sock, port} = create_kernel_listener(ctx.ifaddr)

      on_exit(fn -> :socket.close(listen_sock) end)

      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      connect_task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: ctx.ifaddr_str, port: port})
        end)

      {:ok, client_sock} = accept_connection(listen_sock)

      on_exit(fn -> :socket.close(client_sock) end)

      assert Task.await(connect_task, 5000) == :ok

      # Send multiple messages
      :ok = :socket.send(client_sock, "First")
      :ok = :socket.send(client_sock, "Second")
      :ok = :socket.send(client_sock, "Third")

      # Give time for segments to arrive
      Process.sleep(100)

      # Receive all data (TCP is a stream, so data may be coalesced)
      {:ok, data} = Tricep.recv(socket, 0, 5000)
      assert data == "FirstSecondThird"
    end

    test "times out when no data arrives", ctx do
      {:ok, listen_sock, port} = create_kernel_listener(ctx.ifaddr)

      on_exit(fn -> :socket.close(listen_sock) end)

      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      connect_task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: ctx.ifaddr_str, port: port})
        end)

      {:ok, client_sock} = accept_connection(listen_sock)

      on_exit(fn -> :socket.close(client_sock) end)

      assert Task.await(connect_task, 5000) == :ok

      # Don't send any data, just wait for timeout
      start_time = System.monotonic_time(:millisecond)
      result = Tricep.recv(socket, 0, 200)
      elapsed = System.monotonic_time(:millisecond) - start_time

      assert result == {:error, :timeout}
      # Should have waited approximately 200ms (allow some variance)
      assert elapsed >= 180 and elapsed < 400
    end

    test "recv returns immediately if data already buffered", ctx do
      {:ok, listen_sock, port} = create_kernel_listener(ctx.ifaddr)

      on_exit(fn -> :socket.close(listen_sock) end)

      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      connect_task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: ctx.ifaddr_str, port: port})
        end)

      {:ok, client_sock} = accept_connection(listen_sock)

      on_exit(fn -> :socket.close(client_sock) end)

      assert Task.await(connect_task, 5000) == :ok

      # Send data
      :ok = :socket.send(client_sock, "Buffered data")

      # Wait for data to arrive
      Process.sleep(100)

      # Recv should return immediately
      start_time = System.monotonic_time(:millisecond)
      result = Tricep.recv(socket, 0, 5000)
      elapsed = System.monotonic_time(:millisecond) - start_time

      assert result == {:ok, "Buffered data"}
      assert elapsed < 50
    end
  end

  describe "bidirectional communication" do
    test "echo server pattern", ctx do
      {:ok, listen_sock, port} = create_kernel_listener(ctx.ifaddr)

      on_exit(fn -> :socket.close(listen_sock) end)

      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      connect_task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: ctx.ifaddr_str, port: port})
        end)

      {:ok, client_sock} = accept_connection(listen_sock)

      on_exit(fn -> :socket.close(client_sock) end)

      assert Task.await(connect_task, 5000) == :ok

      # Start echo server on kernel socket
      echo_task =
        Task.async(fn ->
          {:ok, data} = :socket.recv(client_sock, 0, 5000)
          :ok = :socket.send(client_sock, data)
          :ok
        end)

      # Send from Tricep, expect echo back
      assert Tricep.send(socket, "Echo me!") == :ok
      assert Tricep.recv(socket, 0, 5000) == {:ok, "Echo me!"}

      assert Task.await(echo_task, 5000) == :ok
    end

    test "multiple round trips", ctx do
      {:ok, listen_sock, port} = create_kernel_listener(ctx.ifaddr)

      on_exit(fn -> :socket.close(listen_sock) end)

      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      connect_task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: ctx.ifaddr_str, port: port})
        end)

      {:ok, client_sock} = accept_connection(listen_sock)

      on_exit(fn -> :socket.close(client_sock) end)

      assert Task.await(connect_task, 5000) == :ok

      # Multiple round trips
      for i <- 1..5 do
        msg = "Message #{i}"

        # Tricep -> Kernel
        assert Tricep.send(socket, msg) == :ok
        {:ok, received} = :socket.recv(client_sock, 0, 5000)
        assert received == msg

        # Kernel -> Tricep
        reply = "Reply #{i}"
        :ok = :socket.send(client_sock, reply)
        assert Tricep.recv(socket, 0, 5000) == {:ok, reply}
      end
    end
  end

  describe "close/1 integration" do
    test "active close sends FIN to kernel socket", ctx do
      {:ok, listen_sock, port} = create_kernel_listener(ctx.ifaddr)

      on_exit(fn -> :socket.close(listen_sock) end)

      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      connect_task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: ctx.ifaddr_str, port: port})
        end)

      {:ok, client_sock} = accept_connection(listen_sock)

      on_exit(fn -> :socket.close(client_sock) end)

      assert Task.await(connect_task, 5000) == :ok

      # Close Tricep socket
      assert Tricep.close(socket) == :ok

      # Kernel socket should receive EOF (recv returns 0 bytes or closed)
      # Give time for FIN to be processed
      Process.sleep(100)

      result = :socket.recv(client_sock, 0, 1000)
      # Kernel recv returns {:ok, <<>>} on FIN or {:error, :closed}
      assert result in [{:ok, <<>>}, {:error, :closed}]
    end

    test "passive close receives FIN from kernel socket", ctx do
      {:ok, listen_sock, port} = create_kernel_listener(ctx.ifaddr)

      on_exit(fn -> :socket.close(listen_sock) end)

      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      connect_task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: ctx.ifaddr_str, port: port})
        end)

      {:ok, client_sock} = accept_connection(listen_sock)

      assert Task.await(connect_task, 5000) == :ok

      # Close kernel socket (sends FIN to Tricep)
      :socket.close(client_sock)

      # Tricep recv should return EOF
      assert Tricep.recv(socket, 0, 5000) == {:ok, <<>>}
    end

    test "recv returns data then EOF after kernel close", ctx do
      {:ok, listen_sock, port} = create_kernel_listener(ctx.ifaddr)

      on_exit(fn -> :socket.close(listen_sock) end)

      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      connect_task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: ctx.ifaddr_str, port: port})
        end)

      {:ok, client_sock} = accept_connection(listen_sock)

      assert Task.await(connect_task, 5000) == :ok

      # Send data then close kernel socket
      :ok = :socket.send(client_sock, "Final message")
      :socket.close(client_sock)

      # First recv gets the data
      assert Tricep.recv(socket, 0, 5000) == {:ok, "Final message"}

      # Second recv gets EOF
      assert Tricep.recv(socket, 0, 5000) == {:ok, <<>>}
    end

    test "graceful bidirectional close", ctx do
      {:ok, listen_sock, port} = create_kernel_listener(ctx.ifaddr)

      on_exit(fn -> :socket.close(listen_sock) end)

      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      connect_task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: ctx.ifaddr_str, port: port})
        end)

      {:ok, client_sock} = accept_connection(listen_sock)

      on_exit(fn -> :socket.close(client_sock) end)

      assert Task.await(connect_task, 5000) == :ok

      # Exchange some data first
      assert Tricep.send(socket, "Hello") == :ok
      {:ok, "Hello"} = :socket.recv(client_sock, 0, 5000)

      :ok = :socket.send(client_sock, "Goodbye")
      assert Tricep.recv(socket, 0, 5000) == {:ok, "Goodbye"}

      # Close Tricep side
      assert Tricep.close(socket) == :ok

      # Kernel should see EOF
      Process.sleep(100)
      result = :socket.recv(client_sock, 0, 1000)
      assert result in [{:ok, <<>>}, {:error, :closed}]

      # Close kernel side
      :socket.close(client_sock)
    end

    test "close with pending recv waiter", ctx do
      {:ok, listen_sock, port} = create_kernel_listener(ctx.ifaddr)

      on_exit(fn -> :socket.close(listen_sock) end)

      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      connect_task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: ctx.ifaddr_str, port: port})
        end)

      {:ok, client_sock} = accept_connection(listen_sock)

      assert Task.await(connect_task, 5000) == :ok

      # Start recv in background (will block waiting for data)
      recv_task = Task.async(fn -> Tricep.recv(socket, 0, 10_000) end)

      # Give it time to block
      Process.sleep(100)

      # Close kernel socket (sends FIN)
      :socket.close(client_sock)

      # recv should unblock with EOF
      assert Task.await(recv_task, 5000) == {:ok, <<>>}
    end
  end

  # Helper to receive exactly `length` bytes
  defp recv_all(sock, length, timeout) do
    recv_all(sock, length, timeout, <<>>)
  end

  defp recv_all(_sock, 0, _timeout, acc), do: acc

  defp recv_all(sock, remaining, timeout, acc) do
    case :socket.recv(sock, min(remaining, 4096), timeout) do
      {:ok, data} ->
        recv_all(sock, remaining - byte_size(data), timeout, acc <> data)

      {:error, _} = err ->
        err
    end
  end
end
