defmodule Tricep.DummyLinkTest do
  use ExUnit.Case, async: false

  alias Tricep.DummyLink

  test "default owner is the process that starts the link" do
    {:ok, local_addr} = Tricep.Address.from("fd00::10")
    {:ok, remote_addr} = Tricep.Address.from("fd00::11")
    {:ok, link} = DummyLink.start_link(local_addr: local_addr, remote_addr: remote_addr)

    on_exit(fn -> stop_link(link) end)

    packet = <<1, 2, 3, 4>>

    assert Tricep.Link.send(link, packet) == :ok
    assert_receive {:dummy_link_packet, ^link, ^packet}, 1000
    assert DummyLink.get_packets(link) == [packet]
  end

  defp stop_link(link) do
    if Process.alive?(link) do
      GenServer.stop(link)
    end
  catch
    :exit, :noproc -> :ok
    :exit, {:noproc, _} -> :ok
    :exit, :shutdown -> :ok
    :exit, {:shutdown, _} -> :ok
  end
end
