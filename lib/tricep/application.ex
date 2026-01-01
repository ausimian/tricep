defmodule Tricep.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  require Logger

  @link_supervisor Tricep.LinkSupervisor
  @link_registry Tricep.LinkRegistry
  @tcp_socket_registry Tricep.TcpSocketRegistry

  @impl true
  def start(_type, _args) do
    children = [
      {Registry, keys: :unique, name: @link_registry},
      {Registry, keys: :unique, name: @tcp_socket_registry},
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

  def register_link(srcaddr, dstaddr) do
    IO.inspect({srcaddr, dstaddr}, label: "Registering link")

    with {:ok, _pid} <- Registry.register(@link_registry, dstaddr, srcaddr) do
      :ok
    end
  end

  def lookup_link(dstaddr) do
    List.first(Registry.lookup(@link_registry, dstaddr))
  end

  @spec register_socket_pair(any()) :: :ok | {:error, {:already_registered, pid()}}
  def register_socket_pair(pair) do
    with {:ok, _pid} <- Registry.register(@tcp_socket_registry, pair, nil) do
      :ok
    end
  end

  def deregister_socket_pair(pair) do
    Registry.unregister(@tcp_socket_registry, pair)
  end

  @spec lookup_socket_pair(any()) :: nil | pid()
  def lookup_socket_pair(pair) do
    Logger.debug("Looking up socket pair: #{inspect(pair)}")

    case Registry.lookup(@tcp_socket_registry, pair) do
      [{pid, nil}] -> pid
      [] -> nil
    end
  end
end
