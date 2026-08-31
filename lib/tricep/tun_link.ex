defmodule Tricep.TunLink do
  @moduledoc false

  @behaviour :gen_statem

  import Bitwise

  require Logger

  @fragment_timeout_ms 60_000
  @max_fragment_buffers 64
  @max_fragment_reassembly_size 65_535
  @default_tx_queue_packets 256
  @default_tx_queue_bytes 1_048_576

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
    field :fragment_buffers, map(), default: %{}
    # Packets are queued per originating socket and scheduled round-robin so
    # one busy TCP connection cannot monopolise a stalled TUN writer.
    field :tx_queues, map(), default: %{}
    field :tx_order, :queue.queue(pid()), default: :queue.new()
    field :tx_queued_packets, non_neg_integer(), default: 0
    field :tx_queued_bytes, non_neg_integer(), default: 0
    field :tx_queue_packets_limit, pos_integer(), default: @default_tx_queue_packets
    field :tx_queue_bytes_limit, pos_integer(), default: @default_tx_queue_bytes
    # The packet currently handed to Tundra remains accounted until it has
    # accepted the write, including while the device has returned a select.
    field :pending_tx, {pid(), binary()} | nil, default: nil
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
         :ok <- Tricep.Application.register_link(dstaddr_bin, {ifaddr_bin, mtu}),
         :ok <- register_prefix_route(dstaddr_bin, ifaddr_bin, mtu, opts) do
      state = %__MODULE__{tun: tun, mtu: mtu, name: name}

      schedule_read_tun()
      {:ok, :ready, state}
    end
  end

  defp register_prefix_route(srcaddr, dstaddr, mtu, opts) do
    case route_prefix_len(Keyword.get(opts, :netmask)) do
      128 -> :ok
      prefix_len -> Tricep.Application.register_route(srcaddr, dstaddr, prefix_len, mtu)
    end
  end

  defp route_prefix_len(nil), do: 128

  defp route_prefix_len(netmask) do
    with {:ok, mask} <- Tricep.Address.from(netmask),
         {:ok, prefix_len} <- contiguous_prefix_len(mask) do
      prefix_len
    else
      _ -> 128
    end
  end

  defp contiguous_prefix_len(mask) do
    bits = for <<bit::1 <- mask>>, do: bit
    {ones, rest} = Enum.split_while(bits, &(&1 == 1))

    if Enum.all?(rest, &(&1 == 0)) do
      {:ok, length(ones)}
    else
      {:error, :noncontiguous_netmask}
    end
  end

  @impl true
  def handle_event(:info, :read_tun, _, %__MODULE__{} = state) do
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

  def handle_event({:call, from}, {:send, packet}, :ready, %__MODULE__{} = state) do
    enqueue_tx(state, elem(from, 0), packet, from, [{:next_event, :internal, :drain_tx}])
  end

  def handle_event({:call, from}, {:send, packet}, {:waiting, _handle}, %__MODULE__{} = state) do
    enqueue_tx(state, elem(from, 0), packet, from, [])
  end

  def handle_event(:internal, :drain_tx, :ready, %__MODULE__{pending_tx: nil} = state) do
    case dequeue_tx(state) do
      :empty ->
        :keep_state_and_data

      {{source, packet}, state} ->
        {:keep_state, %{state | pending_tx: {source, packet}},
         {:next_event, :internal, :send_pending_tx}}
    end
  end

  def handle_event(:internal, :drain_tx, :ready, %__MODULE__{}), do: :keep_state_and_data

  def handle_event(
        :internal,
        :send_pending_tx,
        :ready,
        %__MODULE__{pending_tx: {_source, packet}} = state
      ) do
    case Tundra.send(state.tun, packet, :nowait) do
      :ok ->
        {:keep_state, complete_pending_tx(state), {:next_event, :internal, :drain_tx}}

      {:select, {:select_info, :send, handle}} ->
        {:next_state, {:waiting, handle}, state}
    end
  end

  def handle_event(
        :info,
        {:"$socket", _tun, :select, handle},
        {:waiting, handle},
        %__MODULE__{} = state
      ) do
    {:next_state, :ready, state, {:next_event, :internal, :send_pending_tx}}
  end

  def handle_event(:info, {:"$socket", tun, :select, _}, _, %__MODULE__{tun: tun}) do
    schedule_read_tun()
  end

  # `Tricep.Link.send/2` normally makes a synchronous admission call. A packet generated
  # by this link while it is handling inbound traffic uses this self-message
  # to avoid a synchronous self-call; it is admitted through the same queue.
  def handle_event(:info, {:send, packet}, :ready, %__MODULE__{} = state) do
    enqueue_unsolicited_tx(state, packet, [{:next_event, :internal, :drain_tx}])
  end

  def handle_event(:info, {:send, packet}, {:waiting, _handle}, %__MODULE__{} = state) do
    enqueue_unsolicited_tx(state, packet, [])
  end

  def handle_event(:info, {:stop, reason}, _, %__MODULE__{} = state) do
    {:stop, reason, state}
  end

  defp enqueue_tx(state, source, packet, from, follow_up_actions) do
    case enqueue_tx_packet(state, source, packet) do
      {:ok, state} ->
        {:keep_state, state, [{:reply, from, :ok} | follow_up_actions]}

      {:error, reason} ->
        {:keep_state_and_data, {:reply, from, {:error, reason}}}
    end
  end

  defp enqueue_unsolicited_tx(state, packet, follow_up_actions) do
    case enqueue_tx_packet(state, self(), packet) do
      {:ok, state} ->
        {:keep_state, state, follow_up_actions}

      {:error, reason} ->
        Logger.warning(
          "Dropping link-originated packet because bounded transmit queue is #{reason}"
        )

        :keep_state_and_data
    end
  end

  defp enqueue_tx_packet(state, source, packet) do
    packet_size = byte_size(packet)

    cond do
      packet_size > state.tx_queue_bytes_limit -> {:error, :emsgsize}
      state.tx_queued_packets >= state.tx_queue_packets_limit -> {:error, :eagain}
      state.tx_queued_bytes + packet_size > state.tx_queue_bytes_limit -> {:error, :eagain}
      true -> {:ok, put_tx_packet(state, source, packet)}
    end
  end

  defp put_tx_packet(state, source, packet) do
    source_queue = Map.get(state.tx_queues, source, :queue.new())
    first_for_source? = :queue.is_empty(source_queue)
    tx_queues = Map.put(state.tx_queues, source, :queue.in(packet, source_queue))
    tx_order = if first_for_source?, do: :queue.in(source, state.tx_order), else: state.tx_order

    %{
      state
      | tx_queues: tx_queues,
        tx_order: tx_order,
        tx_queued_packets: state.tx_queued_packets + 1,
        tx_queued_bytes: state.tx_queued_bytes + byte_size(packet)
    }
  end

  defp dequeue_tx(%__MODULE__{tx_order: order} = state) do
    case :queue.out(order) do
      {:empty, _} ->
        :empty

      {{:value, source}, remaining_order} ->
        source_queue = Map.fetch!(state.tx_queues, source)
        {{:value, packet}, remaining_source_queue} = :queue.out(source_queue)

        {tx_queues, tx_order} =
          if :queue.is_empty(remaining_source_queue) do
            {Map.delete(state.tx_queues, source), remaining_order}
          else
            {Map.put(state.tx_queues, source, remaining_source_queue),
             :queue.in(source, remaining_order)}
          end

        {{source, packet}, %{state | tx_queues: tx_queues, tx_order: tx_order}}
    end
  end

  defp complete_pending_tx(%__MODULE__{pending_tx: {_source, packet}} = state) do
    %{
      state
      | pending_tx: nil,
        tx_queued_packets: state.tx_queued_packets - 1,
        tx_queued_bytes: state.tx_queued_bytes - byte_size(packet)
    }
  end

  @doc false
  def handle_ip_packet(packet, %__MODULE__{} = state) do
    case Tricep.Ip.parse(packet) do
      {:ok, %{next_header: next_header, payload: payload, src: src, dst: dst}} ->
        handle_ipv6_payload(next_header, payload, src, dst, state)

      _ ->
        schedule_read_tun()
    end
  end

  defp handle_ipv6_payload(44, payload, src, dst, state) do
    handle_fragment(payload, src, dst, state)
  end

  defp handle_ipv6_payload(next_header, payload, src, dst, state) do
    # credo:disable-for-next-line Credo.Check.Readability.WithSingleClause
    with {:ok, protocol, data} <- unwrap_ipv6_payload(next_header, payload) do
      handle_ipv6_packet(protocol, data, src, dst, state)
    else
      _ -> schedule_read_tun()
    end
  end

  defp handle_ipv6_packet(prot, data, src, dst, state) do
    case prot do
      6 ->
        handle_tcp(data, src, dst, state)

      17 ->
        handle_udp(data, src, dst, state)

      44 ->
        handle_fragment(data, src, dst, state)

      58 ->
        handle_icmpv6(data, src, dst, state)

      59 ->
        schedule_read_tun()

      _ ->
        schedule_read_tun()
    end
  end

  defp unwrap_ipv6_payload(protocol, payload) when protocol in [6, 17, 44, 58, 59] do
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

  defp handle_fragment(
         <<next_header::8, _reserved::8, offset_flags::16, identification::32,
           fragment_payload::binary>>,
         src,
         dst,
         state
       ) do
    offset = (offset_flags >>> 3) * 8
    more_fragments? = (offset_flags &&& 0x1) == 1

    cond do
      more_fragments? and rem(byte_size(fragment_payload), 8) != 0 ->
        Logger.warning("Dropping malformed IPv6 fragment with non-8-byte payload")
        read_tun_again(state)

      offset + byte_size(fragment_payload) > @max_fragment_reassembly_size ->
        Logger.warning("Dropping oversized IPv6 fragment reassembly")
        read_tun_again(drop_fragment_buffer(state, {src, dst, identification, next_header}))

      true ->
        key = {src, dst, identification, next_header}

        state =
          state
          |> prune_fragment_buffers()
          |> put_fragment(key, offset, fragment_payload, more_fragments?)

        case reassembled_fragment(state, key) do
          {:complete, reassembled_payload, state} ->
            handle_reassembled_fragment(next_header, reassembled_payload, src, dst, state)

          {:error, reason, state} ->
            Logger.warning("Dropping malformed IPv6 fragment set: #{reason}")
            read_tun_again(state)

          :pending ->
            read_tun_again(state)
        end
    end
  end

  defp handle_fragment(_payload, _src, _dst, state) do
    Logger.warning("Dropping truncated IPv6 fragment header")
    read_tun_again(state)
  end

  defp put_fragment(state, key, offset, payload, more_fragments?) do
    now = System.monotonic_time(:millisecond)

    buffer =
      Map.get(state.fragment_buffers, key, %{
        fragments: %{},
        total_length: nil,
        updated_at: now
      })

    total_length =
      if more_fragments? do
        buffer.total_length
      else
        offset + byte_size(payload)
      end

    buffer = %{
      buffer
      | fragments: Map.put(buffer.fragments, offset, payload),
        total_length: total_length,
        updated_at: now
    }

    %{
      state
      | fragment_buffers: limit_fragment_buffers(Map.put(state.fragment_buffers, key, buffer))
    }
  end

  defp reassembled_fragment(%__MODULE__{} = state, key) do
    buffer = Map.fetch!(state.fragment_buffers, key)

    case assemble_fragments(buffer) do
      {:complete, payload} ->
        {:complete, payload, drop_fragment_buffer(state, key)}

      {:error, reason} ->
        {:error, reason, drop_fragment_buffer(state, key)}

      :pending ->
        :pending
    end
  end

  defp assemble_fragments(%{total_length: nil}), do: :pending

  defp assemble_fragments(%{fragments: fragments, total_length: total_length}) do
    fragments
    |> Enum.sort_by(fn {offset, _payload} -> offset end)
    |> assemble_fragments(0, total_length, [])
  end

  defp assemble_fragments([], expected, total_length, acc) when expected == total_length do
    {:complete, acc |> Enum.reverse() |> IO.iodata_to_binary()}
  end

  defp assemble_fragments([], _expected, _total_length, _acc), do: :pending

  defp assemble_fragments([{offset, payload} | rest], expected, total_length, acc) do
    payload_end = offset + byte_size(payload)

    cond do
      offset > expected ->
        :pending

      offset < expected ->
        {:error, :overlap}

      payload_end > total_length ->
        {:error, :exceeds_total_length}

      true ->
        assemble_fragments(rest, payload_end, total_length, [payload | acc])
    end
  end

  defp handle_reassembled_fragment(next_header, payload, src, dst, state) do
    # credo:disable-for-next-line Credo.Check.Readability.WithSingleClause
    with {:ok, protocol, data} <- unwrap_ipv6_payload(next_header, payload) do
      handle_ipv6_packet(protocol, data, src, dst, state)
      {:keep_state, state}
    else
      _ -> read_tun_again(state)
    end
  end

  defp prune_fragment_buffers(%__MODULE__{} = state) do
    now = System.monotonic_time(:millisecond)

    fragment_buffers =
      Map.reject(state.fragment_buffers, fn {_key, %{updated_at: updated_at}} ->
        now - updated_at > @fragment_timeout_ms
      end)

    %{state | fragment_buffers: fragment_buffers}
  end

  defp limit_fragment_buffers(fragment_buffers)
       when map_size(fragment_buffers) <= @max_fragment_buffers do
    fragment_buffers
  end

  defp limit_fragment_buffers(fragment_buffers) do
    {oldest_key, _oldest_buffer} =
      Enum.min_by(fragment_buffers, fn {_key, %{updated_at: updated_at}} -> updated_at end)

    Map.delete(fragment_buffers, oldest_key)
  end

  defp drop_fragment_buffer(%__MODULE__{} = state, key) do
    %{state | fragment_buffers: Map.delete(state.fragment_buffers, key)}
  end

  # Queue the next read as an ordinary mailbox message. This yields after one
  # packet: a synchronous Link.send/2 call already waiting in the mailbox is
  # handled before another ready read can schedule itself.
  defp schedule_read_tun do
    send(self(), :read_tun)
    :keep_state_and_data
  end

  defp read_tun_again(%__MODULE__{} = state) do
    schedule_read_tun()
    {:keep_state, state}
  end

  defp handle_tcp(data, src, dst, _state) do
    Tricep.Socket.handle_packet(src, dst, data)
    schedule_read_tun()
  end

  defp handle_udp(data, _src, _dst, _state) do
    Logger.warning("Ignoring UDP packet (#{byte_size(data)} bytes)")
    schedule_read_tun()
  end

  defp handle_icmpv6(data, src, dst, state) do
    if valid_icmpv6_checksum?(src, dst, data) do
      case parse_icmpv6_error(data) do
        {:ok, event, quoted_packet} ->
          handle_icmpv6_error(event, quoted_packet, src, dst, state)

        :ignore ->
          schedule_read_tun()

        {:error, reason} ->
          Logger.debug("Ignoring malformed ICMPv6 packet: #{reason}")
          schedule_read_tun()
      end
    else
      Logger.debug("Ignoring ICMPv6 packet with invalid checksum")
      schedule_read_tun()
    end
  end

  defp valid_icmpv6_checksum?(src, dst, data)
       when byte_size(src) == 16 and byte_size(dst) == 16 and is_binary(data) and
              byte_size(data) >= 4 do
    Tricep.Nifs.checksum([
      src,
      dst,
      <<byte_size(data)::32, 0::24, 58::8>>,
      data
    ]) == 0
  end

  defp valid_icmpv6_checksum?(_src, _dst, _data), do: false

  defp parse_icmpv6_error(<<1, code, _checksum::16, _unused::32, quoted_packet::binary>>) do
    {:ok, destination_unreachable_event(code), quoted_packet}
  end

  defp parse_icmpv6_error(<<2, 0, _checksum::16, mtu::32, quoted_packet::binary>>) do
    {:ok, {:packet_too_big, mtu}, quoted_packet}
  end

  defp parse_icmpv6_error(<<3, _code, _checksum::16, _unused::32, quoted_packet::binary>>) do
    {:ok, {:soft, :etimedout}, quoted_packet}
  end

  defp parse_icmpv6_error(<<4, _code, _checksum::16, _pointer::32, quoted_packet::binary>>) do
    {:ok, {:soft, :eproto}, quoted_packet}
  end

  defp parse_icmpv6_error(<<_type, _rest::binary>>), do: :ignore
  defp parse_icmpv6_error(_data), do: {:error, :truncated}

  # RFC 1122 section 4.2.3.9 treats no-route reports as soft, while the
  # ICMPv6 administrative, address, and port-unreachable variants are hard.
  defp destination_unreachable_event(code) when code in [1, 3, 4] do
    {:hard, destination_unreachable_reason(code)}
  end

  defp destination_unreachable_event(code), do: {:soft, destination_unreachable_reason(code)}

  defp destination_unreachable_reason(0), do: :enetunreach
  defp destination_unreachable_reason(1), do: :eacces
  defp destination_unreachable_reason(3), do: :ehostunreach
  defp destination_unreachable_reason(4), do: :econnrefused
  defp destination_unreachable_reason(_code), do: :enetunreach

  defp handle_icmpv6_error(event, quoted_packet, src, dst, _state) do
    with {:ok, %{next_header: next_header, payload: payload, src: inner_src, dst: inner_dst}} <-
           Tricep.Ip.parse_quoted(quoted_packet),
         {:ok, 6, tcp_segment} <- unwrap_ipv6_payload(next_header, payload) do
      log_icmpv6_error(event, src, dst, inner_src, inner_dst, tcp_segment)
      Tricep.Socket.handle_icmpv6_error(inner_src, inner_dst, tcp_segment, event)
    else
      _ ->
        Logger.debug("Ignoring ICMPv6 error without quoted TCP packet")
    end

    schedule_read_tun()
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

    Logger.debug(
      "ICMPv6 Packet Too Big mtu=#{mtu} from #{format_addr(src)} to #{format_addr(dst)} for TCP #{format_addr(inner_src)}:#{src_port} -> #{format_addr(inner_dst)}:#{dst_port}"
    )
  end

  defp log_icmpv6_error(
         {classification, reason},
         src,
         dst,
         inner_src,
         inner_dst,
         tcp_segment
       )
       when classification in [:hard, :soft] do
    {src_port, dst_port} = tcp_ports(tcp_segment)

    Logger.debug(
      "ICMPv6 #{classification} #{reason} from #{format_addr(src)} to #{format_addr(dst)} for TCP #{format_addr(inner_src)}:#{src_port} -> #{format_addr(inner_dst)}:#{dst_port}"
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
