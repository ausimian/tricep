{:ok, pid} = Tricep.Link.new(
  ifaddr: "fd00::1",
  dstaddr: "fd00::2",
  netmask: "ffff:ffff:ffff:ffff::",
  mtu: 1500
)
IO.puts("Created TUN link: #{inspect(pid)}")
:sys.get_state(pid) |> IO.inspect(label: "TUN Link State")

Process.sleep(60_000)

Tricep.Link.drop(pid)
IO.puts("Dropped TUN link")
