# Create the TUN link
{:ok, _link} = Tricep.Link.new(
  ifaddr: "fd00::1",
  dstaddr: "fd00::2",
  netmask: "ffff:ffff:ffff:ffff::",
  mtu: 1500
)
IO.puts("Created TUN link")

# Spawn a listener on fd00::1:33333
listener_task = Task.async(fn ->
  {:ok, listen_sock} = :socket.open(:inet6, :stream, :tcp)
  :ok = :socket.setopt(listen_sock, {:socket, :reuseaddr}, true)
  :ok = :socket.bind(listen_sock, %{family: :inet6, addr: {0xfd00, 0, 0, 0, 0, 0, 0, 1}, port: 33333})
  :ok = :socket.listen(listen_sock)
  IO.puts("Listening on [fd00::1]:33333")

  case :socket.accept(listen_sock, 10_000) do
    {:ok, client} ->
      IO.puts("Accepted connection!")
      :socket.close(client)

    {:error, reason} ->
      IO.puts("Accept failed: #{inspect(reason)}")
  end

  :socket.close(listen_sock)
end)

# Give the listener time to start
Process.sleep(1000)

IO.gets("Press Enter to continue...")
IO.puts("Continuing...")

# Open a Tricep TCP socket and connect
{:ok, sock} = Tricep.open(:inet6, :stream, :tcp)
IO.puts("Opened Tricep socket: #{inspect(sock)}")

address = %{family: :inet6, addr: {0xfd00, 0, 0, 0, 0, 0, 0, 1}, port: 33333}
IO.puts("Connecting to [fd00::1]:33333...")

result = Tricep.connect(sock, address)
IO.puts("Connect result: #{inspect(result)}")

# Wait for listener task
Task.await(listener_task, 15_000)

IO.puts("Done")
Process.sleep(1_000)
