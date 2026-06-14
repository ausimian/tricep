defmodule Tricep.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @link_supervisor Tricep.LinkSupervisor
  @link_registry Tricep.LinkRegistry
  @socket_registry Tricep.SocketRegistry
  @any_addr <<0::128>>

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

  def register_route(srcaddr, dstaddr, prefix_len, mtu)
      when is_integer(prefix_len) and prefix_len in 0..128 do
    route_key = route_key(dstaddr, prefix_len)

    with {:ok, _pid} <- Registry.register(@link_registry, route_key, {srcaddr, mtu}) do
      :ok
    end
  end

  def lookup_link(dstaddr) do
    case Registry.lookup(@link_registry, dstaddr) do
      [{_pid, {_srcaddr, _mtu}} | _] = exact_matches ->
        List.first(exact_matches)

      [] ->
        lookup_route(dstaddr)
    end
  end

  def deregister_link(dstaddr) do
    Registry.unregister(@link_registry, dstaddr)
  end

  def deregister_route(dstaddr, prefix_len)
      when is_integer(prefix_len) and prefix_len in 0..128 do
    Registry.unregister(@link_registry, route_key(dstaddr, prefix_len))
  end

  @spec register_socket_pair(any()) :: :ok | {:error, {:already_registered, pid()}}
  def register_socket_pair(pair) do
    register_socket_key(pair)
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

  def register_bound_socket(addr, port) do
    register_addr_port_key(:bound, addr, port)
  end

  def deregister_bound_socket(addr, port) do
    Registry.unregister(@socket_registry, bound_key(addr, port))
  end

  def register_listener(addr, port) do
    register_addr_port_key(:listener, addr, port)
  end

  def deregister_listener(addr, port) do
    Registry.unregister(@socket_registry, listener_key(addr, port))
  end

  def lookup_listener(dst_addr, dst_port) do
    lookup_socket_key(listener_key(dst_addr, dst_port)) ||
      lookup_socket_key(listener_key(@any_addr, dst_port))
  end

  defp lookup_route(dstaddr) do
    route =
      @link_registry
      |> Registry.select([{{:"$1", :"$2", :"$3"}, [], [{{:"$1", :"$2", :"$3"}}]}])
      |> Enum.flat_map(fn
        {{:route, prefix, prefix_len}, pid, {srcaddr, mtu}} ->
          if prefix_match?(dstaddr, prefix, prefix_len) do
            [{prefix_len, pid, {srcaddr, mtu}}]
          else
            []
          end

        _entry ->
          []
      end)
      |> Enum.max_by(fn {prefix_len, _pid, _link} -> prefix_len end, fn -> nil end)

    case route do
      nil -> nil
      {_prefix_len, pid, link} -> {pid, link}
    end
  end

  defp route_key(addr, prefix_len), do: {:route, route_prefix(addr, prefix_len), prefix_len}

  defp prefix_match?(addr, prefix, prefix_len) do
    route_prefix(addr, prefix_len) == prefix
  end

  defp route_prefix(_addr, 0), do: <<0::128>>

  defp route_prefix(addr, 128) when byte_size(addr) == 16, do: addr

  defp route_prefix(addr, prefix_len) when byte_size(addr) == 16 do
    suffix_len = 128 - prefix_len
    <<prefix::bitstring-size(prefix_len), _suffix::bitstring-size(suffix_len)>> = addr
    <<prefix::bitstring, 0::size(suffix_len)>>
  end

  defp register_socket_key(key) do
    with {:ok, _pid} <- Registry.register(@socket_registry, key, nil) do
      :ok
    end
  end

  defp register_addr_port_key(kind, addr, port) do
    case conflicting_addr_port_pid(kind, addr, port) do
      nil -> register_socket_key(addr_port_key(kind, addr, port))
      pid -> {:error, {:already_registered, pid}}
    end
  end

  defp conflicting_addr_port_pid(kind, @any_addr, port) do
    @socket_registry
    |> Registry.select([{{:"$1", :"$2", :_}, [], [{{:"$1", :"$2"}}]}])
    |> Enum.find_value(fn
      {{^kind, _addr, ^port}, pid} -> pid
      _entry -> nil
    end)
  end

  defp conflicting_addr_port_pid(kind, addr, port) do
    lookup_socket_key(addr_port_key(kind, addr, port)) ||
      lookup_socket_key(addr_port_key(kind, @any_addr, port))
  end

  defp lookup_socket_key(key) do
    case Registry.lookup(@socket_registry, key) do
      [{pid, nil}] -> pid
      [] -> nil
    end
  end

  defp addr_port_key(:bound, addr, port), do: bound_key(addr, port)
  defp addr_port_key(:listener, addr, port), do: listener_key(addr, port)
  defp bound_key(addr, port), do: {:bound, addr, port}
  defp listener_key(addr, port), do: {:listener, addr, port}
end
