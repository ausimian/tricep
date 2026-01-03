# Exclude integration tests by default (require TUN device / root privileges)
# Run with: INTEGRATION=true mix test
if System.get_env("INTEGRATION") == "true" do
  import Bitwise, only: [&&&: 2]
  pid = System.pid() |> String.to_integer()
  id = pid &&& 0xFFFE

  ifaddr_str = "fd00::#{Integer.to_string(id, 16)}"
  dstaddr_str = "fd00::#{Integer.to_string(id + 1, 16)}"

  {:ok, link} =
    Tricep.Link.new(
      ifaddr: ifaddr_str,
      dstaddr: dstaddr_str,
      netmask: "ffff:ffff:ffff:ffff::",
      mtu: 1500
    )

  # Wait for address to be available
  {:ok, sock} = :socket.open(:inet6, :stream, :tcp)

  Enum.reduce_while(1..100, :error, fn _, _ ->
    case :socket.bind(sock, %{family: :inet6, addr: {0xFD00, 0, 0, 0, 0, 0, 0, id}, port: 0}) do
      :ok ->
        {:halt, :ok}

      {:error, :eaddrnotavail} ->
        Process.sleep(20)
        {:cont, :error}
    end
  end)

  :socket.close(sock)

  tricep_config =
    [
      link: link,
      ifaddr: {0xFD00, 0, 0, 0, 0, 0, 0, id},
      ifaddr_str: ifaddr_str,
      dstaddr: {0xFD00, 0, 0, 0, 0, 0, 0, id + 1},
      dstaddr_str: dstaddr_str
    ]

  ExUnit.start(tricep: tricep_config)
else
  ExUnit.start(exclude: [:integration])
end
