defmodule Tricep.DummyLink do
  @moduledoc """
  A dummy link for unit testing Socket without a real TUN device.

  DummyLink registers itself with the application registry and captures
  all packets sent to it, allowing tests to verify Socket behavior.

  Address terminology:
  - `local_addr`: The address Socket connects TO (like ifaddr in TunLink)
  - `remote_addr`: The address Socket sends FROM (like dstaddr in TunLink)
  """

  use GenServer

  defstruct [:local_addr, :remote_addr, :packets, :owner]

  @type t :: %__MODULE__{
          local_addr: binary(),
          remote_addr: binary(),
          packets: [binary()],
          owner: pid()
        }

  @doc """
  Starts a DummyLink and registers it for the given addresses.

  Options:
  - `:local_addr` - address Socket connects TO (16 bytes binary or string)
  - `:remote_addr` - address Socket sends FROM (16 bytes binary or string)
  - `:owner` - pid to notify of events (defaults to caller)
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Returns all packets captured by this link.
  """
  @spec get_packets(pid()) :: [binary()]
  def get_packets(pid) do
    GenServer.call(pid, :get_packets)
  end

  @doc """
  Clears captured packets.
  """
  @spec clear_packets(pid()) :: :ok
  def clear_packets(pid) do
    GenServer.call(pid, :clear_packets)
  end

  @doc """
  Waits for a packet to be captured, with timeout.
  Returns `{:ok, packet}` or `{:error, :timeout}`.
  """
  @spec await_packet(pid(), timeout()) :: {:ok, binary()} | {:error, :timeout}
  def await_packet(pid, timeout \\ 1000) do
    GenServer.call(pid, {:await_packet, timeout}, timeout + 100)
  end

  @doc """
  Simulates receiving a packet from the network.
  Sends the TCP segment to the appropriate Socket via handle_packet.
  """
  @spec inject_packet(pid(), binary()) :: :ok
  def inject_packet(pid, tcp_segment) do
    GenServer.cast(pid, {:inject_packet, tcp_segment})
  end

  # Server callbacks

  @impl true
  def init(opts) do
    local_addr = normalize_addr(Keyword.fetch!(opts, :local_addr))
    remote_addr = normalize_addr(Keyword.fetch!(opts, :remote_addr))
    owner = Keyword.get(opts, :owner, self())

    # Register with the application so Socket can find us when connecting to local_addr
    # register_link(srcaddr, dstaddr) -> key=dstaddr, value=srcaddr
    # We want: key=local_addr (what Socket connects to), value=remote_addr (Socket's source)
    :ok = Tricep.Application.register_link(remote_addr, local_addr)

    {:ok,
     %__MODULE__{
       local_addr: local_addr,
       remote_addr: remote_addr,
       packets: [],
       owner: owner
     }}
  end

  @impl true
  def handle_call(:get_packets, _from, state) do
    {:reply, Enum.reverse(state.packets), state}
  end

  def handle_call(:clear_packets, _from, state) do
    {:reply, :ok, %{state | packets: []}}
  end

  def handle_call({:await_packet, timeout}, from, state) do
    case state.packets do
      [packet | rest] ->
        {:reply, {:ok, packet}, %{state | packets: rest}}

      [] ->
        # Wait for a packet to arrive
        Process.send_after(self(), {:await_timeout, from}, timeout)
        {:noreply, Map.put(state, :awaiting, from)}
    end
  end

  @impl true
  def handle_cast({:inject_packet, tcp_segment}, state) do
    # The packet comes "from" local_addr "to" remote_addr (Socket's source)
    # Socket registered pair as {{remote_addr, src_port}, {local_addr, dst_port}}
    Tricep.Socket.handle_packet(state.local_addr, state.remote_addr, tcp_segment)
    {:noreply, state}
  end

  @impl true
  def handle_info({:send, packet}, state) do
    new_state = %{state | packets: [packet | state.packets]}

    # Notify owner
    send(state.owner, {:dummy_link_packet, self(), packet})

    # If someone is waiting for a packet, reply to them
    case Map.get(new_state, :awaiting) do
      nil ->
        {:noreply, new_state}

      from ->
        GenServer.reply(from, {:ok, packet})
        {:noreply, Map.delete(new_state, :awaiting) |> Map.put(:packets, [])}
    end
  end

  def handle_info({:await_timeout, from}, state) do
    case Map.get(state, :awaiting) do
      ^from ->
        GenServer.reply(from, {:error, :timeout})
        {:noreply, Map.delete(state, :awaiting)}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:stop, _reason}, state) do
    {:stop, :normal, state}
  end

  # Helpers

  defp normalize_addr(addr) when is_binary(addr) and byte_size(addr) == 16, do: addr

  defp normalize_addr(addr) when is_binary(addr) do
    {:ok, bin} = Tricep.Address.from(addr)
    bin
  end
end
