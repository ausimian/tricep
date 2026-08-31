defmodule Tricep.Link do
  @moduledoc false

  import Kernel, except: [send: 2]

  def new(opts) when is_list(opts) do
    Tricep.Application.new_link(opts)
  end

  def drop(pid) when is_pid(pid) do
    ref = Process.monitor(pid)
    Kernel.send(pid, {:stop, :shutdown})

    receive do
      {:DOWN, ^ref, :process, ^pid, _reason} -> :ok
    end

    :ok
  end

  # A synchronous admission result, rather than a fire-and-forget message,
  # keeps packets out of a link process mailbox while its device is not
  # writable. The link owns a bounded fair queue and reports temporary
  # saturation explicitly. Do not use a short call timeout here: a timed-out
  # call can still be admitted later, so retrying it as `:eagain` duplicates
  # stream bytes.

  @spec send(pid(), binary()) :: :ok | {:error, :eagain | :emsgsize | :closed}
  def send(pid, packet) when pid == self() and is_binary(packet) do
    # An inbound packet can require an immediate closed-port reset from the
    # link process itself.  A synchronous self-call would deadlock; TunLink
    # routes this legacy self-message through the same bounded queue.
    Kernel.send(pid, {:send, packet})
    :ok
  end

  def send(pid, packet) when is_pid(pid) and is_binary(packet) do
    :gen_statem.call(pid, {:send, packet}, :infinity)
  catch
    :exit, _reason ->
      if Process.alive?(pid), do: {:error, :eagain}, else: {:error, :closed}
  end
end
