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

  test "rejects invalid challenge ACK limiter options in public open forms" do
    for opts <- [
          %{challenge_ack_limit: 0},
          %{challenge_ack_limit: -1},
          %{challenge_ack_limit: "2"},
          %{challenge_ack_interval_ms: 0},
          %{challenge_ack_interval_ms: -1},
          %{challenge_ack_interval_ms: "100"}
        ] do
      assert Tricep.open(:inet6, :stream, opts) == {:error, :einval}
      assert Tricep.open(:inet6, :stream, :tcp, opts) == {:error, :einval}
      assert Tricep.open(:inet6, :stream, :default, opts) == {:error, :einval}
      assert Tricep.Socket.start_link(opts: opts) == {:error, :einval}
    end
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
