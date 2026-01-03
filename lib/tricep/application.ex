defmodule Tricep.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @link_supervisor Tricep.LinkSupervisor
  @link_registry Tricep.LinkRegistry
  @socket_registry Tricep.SocketRegistry

  @impl true
  def start(_type, _args) do
    children = [
      {Registry, keys: :unique, name: @link_registry},
      {Registry, keys: :unique, name: @socket_registry},
      {DynamicSupervisor, strategy: :one_for_one, name: @link_supervisor}
      # Starts a worker by calling: Tricep.Worker.start_link(arg)
      # {Tricep.Worker, arg}
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Tricep.Supervisor]
    Supervisor.start_link(children, opts)
  end

  @spec new_link(keyword()) :: DynamicSupervisor.on_start_child()
  def new_link(opts) do
    DynamicSupervisor.start_child(@link_supervisor, {Tricep.TunLink, opts})
  end

  def register_link(srcaddr, {dstaddr, mtu}) do
    with {:ok, _pid} <- Registry.register(@link_registry, dstaddr, {srcaddr, mtu}) do
      :ok
    end
  end

  def lookup_link(dstaddr) do
    List.first(Registry.lookup(@link_registry, dstaddr))
  end

  def deregister_link(dstaddr) do
    Registry.unregister(@link_registry, dstaddr)
  end

  @spec register_socket_pair(any()) :: :ok | {:error, {:already_registered, pid()}}
  def register_socket_pair(pair) do
    with {:ok, _pid} <- Registry.register(@socket_registry, pair, nil) do
      :ok
    end
  end

  def deregister_socket_pair(pair) do
    Registry.unregister(@socket_registry, pair)
  end

  @spec lookup_socket_pair(any()) :: nil | pid()
  def lookup_socket_pair(pair) do
    case Registry.lookup(@socket_registry, pair) do
      [{pid, nil}] -> pid
      [] -> nil
    end
  end
end
