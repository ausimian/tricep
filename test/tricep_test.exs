defmodule TricepTest do
  use ExUnit.Case, async: false

  test "opens supported option forms and rejects unsupported sockets" do
    for open <- [
          fn -> Tricep.open(:inet6, :stream, %{}) end,
          fn -> Tricep.open(:inet6, :stream, :default, %{}) end
        ] do
      assert {:ok, socket} = open.()
      on_exit(fn -> stop_socket(socket) end)
    end

    assert Tricep.open(:inet, :stream, :tcp) == {:error, :unsupported}
    assert Tricep.open(:inet6, :dgram, :tcp, %{}) == {:error, :unsupported}
  end

  test "default arities delegate to an unopened socket" do
    assert {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)
    on_exit(fn -> stop_socket(socket) end)

    assert Tricep.listen(socket) == {:error, :einval}
    assert Tricep.accept(socket) == {:error, :einval}
    assert Tricep.recv(socket) == {:error, :enotconn}
  end

  defp stop_socket(socket) do
    if Process.alive?(socket), do: :gen_statem.stop(socket)
  catch
    :exit, :noproc -> :ok
    :exit, {:noproc, _} -> :ok
  end
end
