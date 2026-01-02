defmodule Tricep do
  @spec open(:inet6, :stream, :tcp | :default | map()) :: {:ok, pid()} | {:error, :unsupported}
  def open(domain, type, protocol)

  def open(:inet6, :stream, protocol) when protocol in [:tcp, :default] do
    open(:inet6, :stream, protocol, %{})
  end

  def open(:inet6, :stream, opts) when is_map(opts) do
    open(:inet6, :stream, :default, opts)
  end

  def open(_, _, _) do
    {:error, :unsupported}
  end

  @spec open(:inet6, :stream, :tcp | :default, map()) :: {:ok, pid()} | {:error, :unsupported}
  def open(domain, type, protocol, opts)

  def open(:inet6, :stream, :default, opts) do
    open(:inet6, :stream, :tcp, opts)
  end

  def open(:inet6, :stream, :tcp, opts) when is_map(opts) do
    Tricep.Socket.start_link(opts: opts)
  end

  def open(_, _, _, _) do
    {:error, :unsupported}
  end

  defdelegate connect(socket, address), to: Tricep.Socket

  @spec send(pid(), binary()) :: :ok | {:error, atom()}
  def send(socket, data) when is_pid(socket) and is_binary(data) do
    Tricep.Socket.send_data(socket, data)
  end

  @spec recv(pid(), non_neg_integer(), timeout()) :: {:ok, binary()} | {:error, atom()}
  def recv(socket, length \\ 0, timeout \\ :infinity)

  def recv(socket, length, timeout) when is_pid(socket) do
    Tricep.Socket.recv(socket, length, timeout)
  end

  @spec close(pid()) :: :ok | {:error, atom()}
  def close(socket) when is_pid(socket) do
    Tricep.Socket.close(socket)
  end
end
