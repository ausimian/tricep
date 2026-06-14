defmodule Tricep.TunLink do
  @moduledoc false

  @behaviour :gen_statem

  require Logger

  @read_tun_again {:keep_state_and_data, {:next_event, :internal, :read_tun}}

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
         {:ok, mtu} <- Tricep.Nifs.get_mtu(name),
         :ok <- Tricep.Application.register_link(dstaddr_bin, {ifaddr_bin, mtu}) do
      state = %__MODULE__{tun: tun, mtu: mtu, name: name}
      {:ok, :ready, state, {:next_event, :internal, :read_tun}}
    end
  end

  @impl true
  def handle_event(:internal, :read_tun, _, %__MODULE__{} = state) do
    case Tundra.recv(state.tun, state.mtu, :nowait) do
      {:ok, <<>>} ->
        # Empty read on macOS means socket was closed
        {:stop, :normal, state}

      {:ok, ip_packet} ->
        handle_ip_packet(ip_packet, state)

      {:select, _} ->
        :keep_state_and_data
    end
  end

  def handle_event(:info, {:send, packet}, :ready, %__MODULE__{} = state) do
    case Tundra.send(state.tun, packet, :nowait) do
      :ok ->
        :keep_state_and_data

      {:select, {:select_info, :send, handle}} ->
        {:next_state, {:waiting, handle}, state, :postpone}
    end
  end

  # Postpone send messages while waiting for TUN device to become ready
  def handle_event(:info, {:send, _packet}, {:waiting, _handle}, _state) do
    {:keep_state_and_data, :postpone}
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

  @doc false
  def handle_ip_packet(packet, %__MODULE__{} = state) do
    with {:ok, %{next_header: next_header, payload: payload, src: src, dst: dst}} <-
           Tricep.Ip.parse(packet),
         {:ok, protocol, data} <- unwrap_ipv6_payload(next_header, payload) do
      handle_ipv6_packet(protocol, data, src, dst, state)
    else
      _ -> @read_tun_again
    end
  end

  defp handle_ipv6_packet(prot, data, src, dst, state) do
    case prot do
      6 ->
        handle_tcp(data, src, dst, state)

      17 ->
        handle_udp(data, src, dst, state)

      58 ->
        handle_icmpv6(data, src, dst, state)

      59 ->
        @read_tun_again

      _ ->
        @read_tun_again
    end
  end

  defp unwrap_ipv6_payload(protocol, payload) when protocol in [6, 17, 58, 59] do
    {:ok, protocol, payload}
  end

  # Hop-by-Hop Options, Routing, and Destination Options share the same length format.
  defp unwrap_ipv6_payload(protocol, <<next_header::8, header_len::8, rest::binary>>)
       when protocol in [0, 43, 60] do
    extension_len = 6 + header_len * 8

    case rest do
      <<_extension_body::binary-size(extension_len), payload::binary>> ->
        unwrap_ipv6_payload(next_header, payload)

      _ ->
        {:error, :malformed_extension_header}
    end
  end

  defp unwrap_ipv6_payload(_protocol, _payload), do: {:error, :unsupported_protocol}

  defp handle_tcp(data, src, dst, _state) do
    Tricep.Socket.handle_packet(src, dst, data)
    @read_tun_again
  end

  defp handle_udp(data, _src, _dst, _state) do
    Logger.warning("Ignoring UDP packet (#{byte_size(data)} bytes)")
    @read_tun_again
  end

  defp handle_icmpv6(data, src, dst, state) do
    case parse_icmpv6_error(data) do
      {:ok, event, quoted_packet} ->
        handle_icmpv6_error(event, quoted_packet, src, dst, state)

      :ignore ->
        @read_tun_again

      {:error, reason} ->
        Logger.warning("Ignoring malformed ICMPv6 packet: #{reason}")
        @read_tun_again
    end
  end

  defp parse_icmpv6_error(<<1, code, _checksum::16, _unused::32, quoted_packet::binary>>) do
    {:ok, {:hard, destination_unreachable_reason(code)}, quoted_packet}
  end

  defp parse_icmpv6_error(<<2, 0, _checksum::16, mtu::32, quoted_packet::binary>>) do
    {:ok, {:packet_too_big, mtu}, quoted_packet}
  end

  defp parse_icmpv6_error(<<3, _code, _checksum::16, _unused::32, quoted_packet::binary>>) do
    {:ok, {:hard, :etimedout}, quoted_packet}
  end

  defp parse_icmpv6_error(<<4, _code, _checksum::16, _pointer::32, quoted_packet::binary>>) do
    {:ok, {:hard, :eproto}, quoted_packet}
  end

  defp parse_icmpv6_error(<<_type, _rest::binary>>), do: :ignore
  defp parse_icmpv6_error(_data), do: {:error, :truncated}

  defp destination_unreachable_reason(0), do: :enetunreach
  defp destination_unreachable_reason(1), do: :eacces
  defp destination_unreachable_reason(3), do: :ehostunreach
  defp destination_unreachable_reason(4), do: :econnrefused
  defp destination_unreachable_reason(_code), do: :enetunreach

  defp handle_icmpv6_error(event, quoted_packet, src, dst, _state) do
    with {:ok, %{next_header: next_header, payload: payload, src: inner_src, dst: inner_dst}} <-
           Tricep.Ip.parse(quoted_packet),
         {:ok, 6, tcp_segment} <- unwrap_ipv6_payload(next_header, payload) do
      log_icmpv6_error(event, src, dst, inner_src, inner_dst, tcp_segment)
      Tricep.Socket.handle_icmpv6_error(inner_src, inner_dst, tcp_segment, event)
    else
      _ ->
        Logger.warning("Ignoring ICMPv6 error without quoted TCP packet")
    end

    @read_tun_again
  end

  defp log_icmpv6_error(
         {:packet_too_big, mtu},
         src,
         dst,
         inner_src,
         inner_dst,
         tcp_segment
       ) do
    {src_port, dst_port} = tcp_ports(tcp_segment)

    Logger.warning(
      "ICMPv6 Packet Too Big mtu=#{mtu} from #{format_addr(src)} to #{format_addr(dst)} for TCP #{format_addr(inner_src)}:#{src_port} -> #{format_addr(inner_dst)}:#{dst_port}"
    )
  end

  defp log_icmpv6_error({:hard, reason}, src, dst, inner_src, inner_dst, tcp_segment) do
    {src_port, dst_port} = tcp_ports(tcp_segment)

    Logger.warning(
      "ICMPv6 #{reason} from #{format_addr(src)} to #{format_addr(dst)} for TCP #{format_addr(inner_src)}:#{src_port} -> #{format_addr(inner_dst)}:#{dst_port}"
    )
  end

  defp tcp_ports(<<src_port::16, dst_port::16, _rest::binary>>), do: {src_port, dst_port}
  defp tcp_ports(_segment), do: {:unknown, :unknown}

  defp format_addr(<<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>) do
    {a, b, c, d, e, f, g, h}
    |> :inet.ntoa()
    |> to_string()
  end

  defp format_addr(addr), do: inspect(addr)
end
