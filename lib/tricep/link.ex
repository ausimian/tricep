defmodule Tricep.Link do
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

  @spec send(pid(), binary()) :: :ok
  def send(pid, packet) when is_pid(pid) and is_binary(packet) do
    Kernel.send(pid, {:send, packet})
    :ok
  end
end
