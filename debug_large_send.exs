#!/usr/bin/env elixir

# Debug script for large data send test
# Run with: sudo elixir debug_large_send.exs

import Bitwise

# Generate unique addresses based on PID
pid = System.pid() |> String.to_integer()
id = pid &&& 0xFFFE

ifaddr_str = "fd00::#{Integer.to_string(id, 16)}"
dstaddr_str = "fd00::#{Integer.to_string(id + 1, 16)}"

IO.puts("Starting TUN link...")
IO.puts("  ifaddr: #{ifaddr_str}")
IO.puts("  dstaddr: #{dstaddr_str}")

{:ok, link} =
  Tricep.Link.new(
    ifaddr: ifaddr_str,
    dstaddr: dstaddr_str,
    netmask: "ffff:ffff:ffff:ffff::",
    mtu: 1500
  )

# Get the TUN interface name
Process.sleep(100)

# Find the tun interface
{output, 0} = System.cmd("ip", ["link", "show"])
tun_name =
  output
  |> String.split("\n")
  |> Enum.find_value(fn line ->
    if String.contains?(line, "tun") do
      line |> String.split(":") |> Enum.at(1) |> String.trim()
    end
  end)

IO.puts("TUN interface: #{tun_name || "not found"}")

# Start tcpdump in background
tcpdump_file = "/tmp/tricep_debug.pcap"
IO.puts("\nStarting tcpdump, writing to #{tcpdump_file}...")

tcpdump_port =
  Port.open({:spawn, "tcpdump -i #{tun_name || "any"} -w #{tcpdump_file} -s 0 ip6 2>&1"}, [:binary])

Process.sleep(500)

# Wait for address to be available
{:ok, sock} = :socket.open(:inet6, :stream, :tcp)

Enum.reduce_while(1..100, :error, fn _, _ ->
  case :socket.bind(sock, %{family: :inet6, addr: {0xFD00, 0, 0, 0, 0, 0, 0, id}, port: 0}) do
    :ok -> {:halt, :ok}
    {:error, :eaddrnotavail} ->
      Process.sleep(20)
      {:cont, :error}
  end
end)

:socket.close(sock)

IO.puts("\nCreating kernel listener...")

# Create kernel listener
{:ok, listen_sock} = :socket.open(:inet6, :stream, :tcp)
:ok = :socket.setopt(listen_sock, {:socket, :reuseaddr}, true)
:ok = :socket.bind(listen_sock, %{family: :inet6, addr: {0xFD00, 0, 0, 0, 0, 0, 0, id}, port: 0})
:ok = :socket.listen(listen_sock)
{:ok, %{port: port}} = :socket.sockname(listen_sock)

IO.puts("Listening on port #{port}")

# Open Tricep socket
IO.puts("\nOpening Tricep socket...")
{:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

# Connect in background
IO.puts("Connecting to #{ifaddr_str}:#{port}...")

connect_task =
  Task.async(fn ->
    Tricep.connect(socket, %{family: :inet6, addr: ifaddr_str, port: port})
  end)

# Accept connection
IO.puts("Waiting for connection...")
{:ok, client_sock} = :socket.accept(listen_sock, 5000)
IO.puts("Connection accepted!")

# Wait for connect to complete
:ok = Task.await(connect_task, 5000)
IO.puts("Tricep connected!")

# Send large data
large_data = :crypto.strong_rand_bytes(5000)
IO.puts("\nSending #{byte_size(large_data)} bytes through Tricep...")

send_result = Tricep.send(socket, large_data)
IO.puts("Send result: #{inspect(send_result)}")

# Try to receive
IO.puts("\nReceiving on kernel socket (5 second timeout)...")

defmodule RecvHelper do
  def recv_all(sock, remaining, timeout, acc \\ <<>>) do
    if remaining <= 0 do
      acc
    else
      case :socket.recv(sock, min(remaining, 4096), timeout) do
        {:ok, data} ->
          IO.puts("  Received #{byte_size(data)} bytes")
          recv_all(sock, remaining - byte_size(data), timeout, acc <> data)
        {:error, reason} = err ->
          IO.puts("  Recv error: #{inspect(reason)}, got #{byte_size(acc)} bytes so far")
          err
      end
    end
  end
end

result = RecvHelper.recv_all(client_sock, 5000, 5000)

case result do
  data when is_binary(data) ->
    IO.puts("\nSuccess! Received #{byte_size(data)} bytes")
    IO.puts("Data matches: #{data == large_data}")
  {:error, reason} ->
    IO.puts("\nFailed with: #{inspect(reason)}")
end

# Cleanup
IO.puts("\nCleaning up...")
:socket.close(client_sock)
:socket.close(listen_sock)

# Stop tcpdump
Process.sleep(500)
Port.close(tcpdump_port)
System.cmd("pkill", ["-f", "tcpdump.*#{tcpdump_file}"])

IO.puts("\nPacket capture saved to: #{tcpdump_file}")
IO.puts("View with: tcpdump -r #{tcpdump_file} -vvv")
IO.puts("Or: wireshark #{tcpdump_file}")
