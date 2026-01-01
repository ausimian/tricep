defmodule Tricep.Link do
  import Kernel, except: [send: 2]

  def new(opts) when is_list(opts) do
    Tricep.Application.new_link(opts)
  end

  def drop(pid) when is_pid(pid) do
    Kernel.send(pid, {:stop, :shutdown})
    :ok
  end

  @spec send(pid(), binary()) :: :ok
  def send(pid, packet) when is_pid(pid) and is_binary(packet) do
    Kernel.send(pid, {:send, packet})
    :ok
  end
end
