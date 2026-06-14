defmodule Tricep.IntegrationCase do
  @moduledoc """
  Test case template for integration tests that require TUN device access.

  These tests require root privileges or CAP_NET_ADMIN capability.
  They are excluded by default and can be run with:

      mix test --include integration

  Or run only integration tests:

      mix test --only integration
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      use ExUnit.Case, async: false

      @moduletag :integration

      import Tricep.IntegrationCase
    end
  end

  @doc """
  Creates a listening TCP socket on the kernel network stack.
  Returns `{:ok, listen_socket, port}` or `{:error, reason}`.
  Uses ephemeral port by default (port 0).
  """
  def create_kernel_listener(addr, port \\ 0, attempts \\ 100)
  def create_kernel_listener(_addr, _port, 0), do: {:error, :eaddrnotavail}

  def create_kernel_listener(addr, port, attempts) do
    {:ok, sock} = :socket.open(:inet6, :stream, :tcp)
    :ok = :socket.setopt(sock, {:socket, :reuseaddr}, true)

    case :socket.bind(sock, %{family: :inet6, addr: addr, port: port}) do
      :ok ->
        :ok = :socket.listen(sock)
        {:ok, %{port: actual_port}} = :socket.sockname(sock)
        {:ok, sock, actual_port}

      {:error, :eaddrnotavail} ->
        :socket.close(sock)
        Process.sleep(20)
        create_kernel_listener(addr, port, attempts - 1)
    end
  end

  @doc """
  Accepts a connection on the listener socket with a timeout.
  """
  def accept_connection(listen_sock, timeout \\ 5_000) do
    :socket.accept(listen_sock, timeout)
  end

  def wait_for_recv_waiters(socket, count \\ 1, timeout \\ 1_000) do
    wait_for_socket(socket, timeout, fn
      {_state_name, %{recv_waiters: waiters}} -> length(waiters) >= count
      _ -> false
    end)
  end

  def wait_for_recv_buffer(socket, bytes, timeout \\ 5_000) do
    wait_for_socket(socket, timeout, fn
      {_state_name, %{recv_buffer: buffer}} -> byte_size(buffer) >= bytes
      _ -> false
    end)
  end

  defp wait_for_socket(socket, timeout, predicate) do
    deadline = System.monotonic_time(:millisecond) + timeout
    wait_for_socket(socket, deadline, predicate, nil)
  end

  defp wait_for_socket(socket, deadline, predicate, last_state) do
    state = :sys.get_state(socket)

    cond do
      predicate.(state) ->
        state

      System.monotonic_time(:millisecond) >= deadline ->
        flunk("socket did not reach expected state; last state: #{inspect(last_state || state)}")

      true ->
        Process.sleep(1)
        wait_for_socket(socket, deadline, predicate, state)
    end
  end
end
