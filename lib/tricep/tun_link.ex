defmodule Tricep.TunLink do
  @behaviour :gen_statem

  require Logger

  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      restart: :temporary,
      type: :worker
    }
  end

  @spec start_link(any()) :: :ignore | {:error, any()} | {:ok, pid()}
  def start_link(opts) do
    :gen_statem.start_link(__MODULE__, opts, hibernate_after: 15_000)
  end

  use TypedStruct

  typedstruct enforce: true do
    field :tun, Tundra.tun_device()
    field :name, String.t()
    field :mtu, non_neg_integer() | nil, default: nil
    field :tph, binary()
  end

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init(opts) do
    ifaddr = Keyword.fetch!(opts, :ifaddr)
    dstaddr = Keyword.fetch!(opts, :dstaddr)
    ifopts = Keyword.take(opts, [:dstaddr, :netmask, :mtu])

    tph =
      case :os.type() do
        {:unix, :linux} -> <<0::16, 0x86DD::16>>
        {:unix, :darwin} -> <<30::32-big>>
      end

    with {:ok, ifaddr_bin} <- Tricep.Address.from(ifaddr),
         {:ok, dstaddr_bin} <- Tricep.Address.from(dstaddr),
         {:ok, {tun, name}} <- Tundra.create(ifaddr, ifopts),
         :ok <- Tricep.Application.register_link(dstaddr_bin, ifaddr_bin) do
      {:ok, :ready, %__MODULE__{tun: tun, name: name, tph: tph}, {:next_event, :internal, :read_mtu}}
    end
  end

  @impl true
  def handle_event(:internal, :read_mtu, :ready, %__MODULE__{mtu: nil} = state) do
    case Tricep.Nifs.get_mtu(state.name) do
      {:ok, mtu} ->
        {:keep_state, %{state | mtu: mtu + 4}, {:next_event, :internal, :read_tun}}

      {:error, _} = err ->
        {:stop, err, state}
    end
  end

  def handle_event(:internal, :read_tun, _, %__MODULE__{} = state) do
    case Tundra.recv(state.tun, state.mtu, :nowait) do
      {:ok, <<_::32, ip_packet::binary>>} ->
        handle_ip_packet(ip_packet, state)

      {:ok, <<>>} ->
        # Empty read on macOS means socket was closed
        {:stop, :normal, state}

      {:select, _} ->
        :keep_state_and_data
    end
  end

  def handle_event(:info, {:send, packet}, :ready, %__MODULE__{} = state) do
    frame = [state.tph, packet]

    case Tundra.send(state.tun, frame, :nowait) do
      :ok ->
        :keep_state_and_data

      {:select, {:select_info, :send, handle}} ->
        {:next_state, {:waiting, handle}, state, :postpone}
    end
  end

  def handle_event(:info, {:"$socket", _tun, :select, handle}, {:waiting, handle}, state) do
    {:next_state, :ready, state, {:next_event, :internal, :read_tun}}
  end

  def handle_event(:info, {:"$socket", tun, :select, _}, _, %__MODULE__{tun: tun}) do
    {:keep_state_and_data, {:next_event, :internal, :read_tun}}
  end

  def handle_event(:info, {:stop, reason}, _, %__MODULE__{} = state) do
    {:stop, reason, state}
  end

  defp handle_ip_packet(packet, %__MODULE__{} = state) do
    <<6::4, _::28, len::16, nh::8, _::8, src::binary-size(16), dst::binary-size(16),
      rest::binary>> = packet

    handle_ipv6_packet(nh, len, rest, src, dst, state)
  end

  defp handle_ipv6_packet(prot, len, data, src, dst, state) do
    case prot do
      6 ->
        handle_tcp(data, src, dst, state)

      17 ->
        handle_udp(data, src, dst, state)

      58 ->
        handle_icmpv6(data, src, dst, state)

      59 ->
        {:keep_state_and_data, {:next_event, :internal, :read_tun}}

      _ ->
        <<nh::8, hlen::8, _::binary-size(6 + 8 * hlen), rest::binary>> = data
        handle_ipv6_packet(nh, len - (8 + 8 * hlen), rest, src, dst, state)
    end

    {:keep_state_and_data, {:next_event, :internal, :read_tun}}
  end

  defp handle_tcp(data, src, dst, _state) do
    Tricep.Socket.handle_packet(src, dst, data)
    {:keep_state_and_data, {:next_event, :internal, :read_tun}}
  end

  defp handle_udp(data, _src, _dst, _state) do
    Logger.warning("Ignoring UDP packet (#{byte_size(data)} bytes)")
    {:keep_state_and_data, {:next_event, :internal, :read_tun}}
  end

  defp handle_icmpv6(_data, _src, _dst, _state) do
    {:keep_state_and_data, {:next_event, :internal, :read_tun}}
  end
end
