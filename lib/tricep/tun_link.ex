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
  end

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init(opts) do
    ifaddr = Keyword.fetch!(opts, :ifaddr)
    dstaddr = Keyword.fetch!(opts, :dstaddr)
    ifopts = Keyword.take(opts, [:dstaddr, :netmask, :mtu])

    with {:ok, ifaddr_bin} <- Tricep.Address.from(ifaddr),
         {:ok, dstaddr_bin} <- Tricep.Address.from(dstaddr),
         {:ok, {tun, name}} <- Tundra.create(ifaddr, ifopts),
         :ok <- Tricep.Application.register_link(dstaddr_bin, ifaddr_bin) do
      {:ok, :ready, %__MODULE__{tun: tun, name: name}, {:next_event, :internal, :read_mtu}}
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
        Logger.debug("Rcvd #{byte_size(ip_packet)} bytes on #{state.name}")
        handle_ip_packet(ip_packet, state)

      {:select, _} ->
        :keep_state_and_data
    end
  end

  def handle_event(:info, {:send, packet}, :ready, %__MODULE__{} = state) do
    # TUN devices expect a 4-byte header: 2 bytes flags + 2 bytes protocol (Linux)
    # For IPv6: protocol = 0x86DD
    # TODO: macOS uses a different header format (4-byte AF in host byte order, AF_INET6 = 30)
    frame = <<0::16, 0x86DD::16, packet::binary>>

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
        Logger.debug("Ignoring IPv6 No Next Header packet (#{len} bytes)")
        {:keep_state_and_data, {:next_event, :internal, :read_tun}}

      _ ->
        <<nh::8, hlen::8, _::binary-size(6 + 8 * hlen), rest::binary>> = data
        handle_ipv6_packet(nh, len - (8 + 8 * hlen), rest, src, dst, state)
    end

    Logger.debug("Handling IPv6 packet (#{len} bytes) with protocol #{prot}")
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

  defp handle_icmpv6(data, _src, _dst, _state) do
    Logger.debug("Handling ICMPv6 packet (#{byte_size(data)} bytes)")
    {:keep_state_and_data, {:next_event, :internal, :read_tun}}
  end
end
