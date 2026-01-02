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
end
