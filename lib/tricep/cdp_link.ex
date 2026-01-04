defmodule Tricep.CdpLink do
  use GenServer, restart: :temporary
  use TypedStruct

  alias Tricep.Address

  @spec xfer_socket(pid(), :ssl.sslsocket()) :: :ok
  def xfer_socket(pid, socket) when is_pid(pid) do
    with :ok <- :ssl.controlling_process(socket, pid) do
      GenServer.call(pid, {:xfer_socket, socket})
    end
  end

  @spec start_link(any()) :: :ignore | {:error, any()} | {:ok, pid()}
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, hibernate_after: 15_000)
  end

  typedstruct enforce: true do
    field :mtu, pos_integer()
    field :ifaddr_bin, binary()
    field :dstaddr_bin, binary()
    field :ssl, :ssl.sslsocket() | nil, default: nil
    field :buffer, binary(), default: <<>>
  end

  @impl true
  def init(opts) do
    response = Keyword.fetch!(opts, :response)
    mtu = get_in(response, ["clientParameters", "mtu"]) || 1500
    {:ok, dstaddr_bin} = Address.from(get_in(response, ["clientParameters", "address"]))
    {:ok, ifaddr_bin} = Address.from(get_in(response, ["serverAddress"]))
    {:ok, %__MODULE__{mtu: mtu, ifaddr_bin: ifaddr_bin, dstaddr_bin: dstaddr_bin}}
  end

  @impl true
  def handle_call({:xfer_socket, sock}, _from, %__MODULE__{} = state) do
    if is_nil(state.ssl) do
      :ok = Tricep.Application.register_link(state.dstaddr_bin, {state.ifaddr_bin, state.mtu})
      :ok = :ssl.setopts(sock, active: true)
      {:reply, :ok, %__MODULE__{state | ssl: sock}}
    else
      {:reply, {:error, :already_transferred}, state}
    end
  end

  @impl true
  def handle_info({:ssl, _sock, data}, %__MODULE__{} = state) do
    buffer = state.buffer <> data
    {packets, remaining} = frame_packets(buffer, [])

    Enum.each(packets, &handle_ip_packet(&1, state))
    {:noreply, %{state | buffer: remaining}}
  end

  def handle_info({:send, packet}, %__MODULE__{ssl: ssl} = state) do
    :ok = :ssl.send(ssl, packet)
    {:noreply, state}
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

    {:noreply, state}
  end

  defp handle_tcp(data, src, dst, state) do
    Tricep.Socket.handle_packet(src, dst, data)
    {:noreply, state}
  end

  defp handle_udp(_data, _src, _dst, state) do
    {:noreply, state}
  end

  defp handle_icmpv6(_data, _src, _dst, state) do
    {:noreply, state}
  end

  defp frame_packets(<<6::4, _::4, _::24, len::16, _::binary>> = data, acc)
       when byte_size(data) >= 40 + len do
    packet_size = 40 + len
    <<packet::binary-size(packet_size), rest::binary>> = data
    frame_packets(rest, [packet | acc])
  end

  defp frame_packets(data, acc) do
    {Enum.reverse(acc), data}
  end
end
