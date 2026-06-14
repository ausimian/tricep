defmodule Tricep.Socket do
  @moduledoc false

  @behaviour :gen_statem

  import Bitwise

  alias Tricep.Application
  alias Tricep.DataBuffer
  alias Tricep.Tcp

  @type socket_timeout :: non_neg_integer() | :infinity | :nowait
  @type select_info :: {:select_info, :connect | :recv | :send, reference()}

  @spec connect(pid(), :socket.sockaddr_in6(), socket_timeout()) ::
          :ok | {:error, any()} | {:select, select_info()}
  def connect(pid, address, timeout \\ :infinity) when is_pid(pid) do
    :gen_statem.call(pid, {:connect, address, timeout})
  end

  @spec send_data(pid(), binary(), socket_timeout()) ::
          :ok | {:error, atom()} | {:select, select_info()}
  def send_data(pid, data, timeout \\ :infinity) when is_pid(pid) and is_binary(data) do
    :gen_statem.call(pid, {:send, data, timeout})
  end

  @spec recv(pid(), non_neg_integer(), socket_timeout()) ::
          {:ok, binary()} | {:error, atom()} | {:select, select_info()}
  def recv(pid, length \\ 0, timeout \\ :infinity) when is_pid(pid) do
    :gen_statem.call(pid, {:recv, length, timeout})
  end

  @spec close(pid()) :: :ok | {:error, atom()}
  def close(pid) when is_pid(pid) do
    :gen_statem.call(pid, :close)
  end

  @spec shutdown(pid(), :read | :write | :read_write) :: :ok | {:error, atom()}
  def shutdown(pid, how) when is_pid(pid) and how in [:read, :write, :read_write] do
    :gen_statem.call(pid, {:shutdown, how})
  end

  def handle_packet(src_addr, dst_addr, <<src_port::16, dst_port::16, _::binary>> = segment) do
    if Tcp.valid_checksum?(src_addr, dst_addr, segment) do
      pair = {{dst_addr, dst_port}, {src_addr, src_port}}

      if pid = Application.lookup_socket_pair(pair) do
        send(pid, segment)
      end
    end

    :ok
  end

  # Ignore malformed packets that are too short to parse
  def handle_packet(_src_addr, _dst_addr, _segment), do: :ok

  def handle_icmpv6_error(
        src_addr,
        dst_addr,
        <<src_port::16, dst_port::16, _::binary>>,
        event
      ) do
    pair = {{src_addr, src_port}, {dst_addr, dst_port}}

    if pid = Application.lookup_socket_pair(pair) do
      send(pid, {:icmpv6_error, event})
    end

    :ok
  end

  def handle_icmpv6_error(_src_addr, _dst_addr, _segment, _event), do: :ok

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

  # Default MSS for IPv6 (1280 min MTU - 40 IPv6 header - 20 TCP header)
  @default_mss 1220
  @default_recv_buffer_size 65_535
  @max_tcp_window 65_535
  @default_fin_wait_2_timeout_ms 60_000

  # Retransmission timeout constants
  @initial_rto_ms 1_000
  @max_rto_ms 60_000
  @max_retransmit_count 5
  @initial_persist_timeout_ms 1_000
  @max_persist_timeout_ms 60_000

  @typep addr_port() :: {binary(), non_neg_integer()}
  typedstruct enforce: true do
    field :pair, {addr_port(), addr_port()}
    field :link, pid()
    field :iss, non_neg_integer() | nil, default: nil
    field :snd_una, non_neg_integer() | nil, default: nil
    field :snd_nxt, non_neg_integer() | nil, default: nil
    field :snd_wnd, non_neg_integer() | nil, default: nil
    field :irs, non_neg_integer() | nil, default: nil
    field :rcv_nxt, non_neg_integer() | nil, default: nil
    field :rcv_wnd, non_neg_integer() | nil, default: nil
    # MSS we advertise to peer (what we can receive)
    field :rcv_mss, non_neg_integer() | nil, default: nil
    # MSS peer advertised (max we can send)
    field :snd_mss, non_neg_integer() | nil, default: nil
    # Buffers for data transfer
    field :send_buffer, DataBuffer.t(), default: DataBuffer.new()
    field :recv_buffer, binary(), default: <<>>
    field :recv_buffer_size, pos_integer(), default: @default_recv_buffer_size
    # Callers waiting on recv (list of {from, length, timer_ref})
    field :recv_waiters, list(), default: []
    # Track if peer has sent FIN (EOF)
    field :fin_received, boolean(), default: false
    # Retransmission support: list of {seq_start, seq_end, payload | :fin, retransmit_count}
    field :unacked_segments, list(), default: []
    # Current RTO in milliseconds
    field :rto_ms, non_neg_integer(), default: 1_000
    # Whether the RTO timer is currently active
    field :rto_timer_active, boolean(), default: false
    # Zero-window persist timer state
    field :persist_timer_active, boolean(), default: false
    field :persist_timeout_ms, non_neg_integer(), default: @initial_persist_timeout_ms
    # SYN retransmit count (for connection phase)
    field :syn_retransmit_count, non_neg_integer(), default: 0
    # For :nowait connect readiness/completion - [{caller_pid, ref}]
    field :connect_selects, [{pid(), reference()}], default: []
    # For :nowait recv - [{caller_pid, ref, length}]
    field :recv_selects, [{pid(), reference(), non_neg_integer()}], default: []
    # For send backpressure - [{caller_pid, ref} | {from, ref, data, timer_ref}]
    field :send_waiters, list(), default: []
    # Track if read side has been shutdown
    field :read_shutdown, boolean(), default: false
    # Track if write side has been shutdown while queued data drains
    field :write_shutdown, boolean(), default: false
    # How long to wait in FIN_WAIT_2 for the peer FIN
    field :fin_wait_2_timeout_ms, pos_integer(), default: @default_fin_wait_2_timeout_ms
  end

  # TIME_WAIT duration (2*MSL - using short value for TUN-based stack)
  @time_wait_ms 2_000

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init(opts) do
    {:ok, :closed, %{socket_opts: socket_opts(opts)}}
  end

  @impl true
  def handle_event({:call, from}, {:connect, address, timeout}, :closed, closed_data) do
    case validate_sockaddr_in6(address) do
      {:ok, dstaddr_bin, dst_port} ->
        case Application.lookup_link(dstaddr_bin) do
          {pid, {srcaddr_bin, mtu}} ->
            pair = allocate_port(srcaddr_bin, {dstaddr_bin, dst_port})
            send_syn = {:next_event, :internal, {:send_syn, from, timeout}}
            recv_buffer_size = recv_buffer_size(closed_data)

            state = %__MODULE__{
              pair: pair,
              link: pid,
              rcv_mss: mtu - 60,
              recv_buffer_size: recv_buffer_size,
              rcv_wnd: recv_buffer_size,
              fin_wait_2_timeout_ms: fin_wait_2_timeout_ms(closed_data)
            }

            {:next_state, :closed, state, send_syn}

          nil ->
            {:keep_state_and_data, {:reply, from, {:error, :enetunreach}}}
        end

      {:error, reason} ->
        {:keep_state_and_data, {:reply, from, {:error, reason}}}
    end
  end

  # Connect completion after :nowait readiness - consume one retry per registered selector
  def handle_event(
        {:call, {caller_pid, _} = from},
        {:connect, _address, _timeout},
        :established,
        %__MODULE__{} = state
      ) do
    case take_select_for_pid(state.connect_selects, caller_pid) do
      {{^caller_pid, _ref}, remaining_selects} ->
        {:keep_state, %{state | connect_selects: remaining_selects}, {:reply, from, :ok}}

      nil ->
        {:keep_state_and_data, {:reply, from, {:error, :eisconn}}}
    end
  end

  def handle_event(
        {:call, {caller_pid, _} = from},
        {:connect, _address, _timeout},
        {:connect_failed, connect_selects, reason},
        nil
      ) do
    case take_select_for_pid(connect_selects, caller_pid) do
      {{^caller_pid, _ref}, []} ->
        {:next_state, :closed, nil, {:reply, from, {:error, reason}}}

      {{^caller_pid, _ref}, remaining_selects} ->
        {:next_state, {:connect_failed, remaining_selects, reason}, nil,
         {:reply, from, {:error, reason}}}

      nil ->
        {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
    end
  end

  def handle_event(
        {:call, {caller_pid, _} = from},
        {:connect, _address, :nowait},
        {:syn_sent, :nowait},
        %__MODULE__{} = state
      ) do
    ref = make_ref()
    new_state = %{state | connect_selects: state.connect_selects ++ [{caller_pid, ref}]}
    {:keep_state, new_state, {:reply, from, {:select, {:select_info, :connect, ref}}}}
  end

  def handle_event({:call, from}, {:connect, _address, _timeout}, _, %__MODULE__{}) do
    {:keep_state_and_data, {:reply, from, {:error, :eisconn}}}
  end

  def handle_event(:internal, {:send_syn, from, timeout}, :closed, %__MODULE__{} = state) do
    iss = :crypto.strong_rand_bytes(4) |> :binary.decode_unsigned()
    rcv_wnd = receive_window(state)

    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(state.pair, iss, 0, [:syn], rcv_wnd, mss: state.rcv_mss)

    packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
    :ok = Tricep.Link.send(state.link, packet)

    base_state = %{
      state
      | iss: iss,
        snd_una: iss,
        snd_nxt: iss + 1,
        snd_wnd: 0,
        rcv_wnd: rcv_wnd,
        syn_retransmit_count: 0,
        rto_ms: @initial_rto_ms
    }

    case timeout do
      :nowait ->
        # Return select tuple immediately, store caller info for notification
        ref = make_ref()
        {caller_pid, _} = from
        new_state = %{base_state | connect_selects: [{caller_pid, ref}]}

        actions = [
          {{:timeout, :rto}, @initial_rto_ms, :syn_timeout_nowait},
          {:reply, from, {:select, {:select_info, :connect, ref}}}
        ]

        {:next_state, {:syn_sent, :nowait}, new_state, actions}

      :infinity ->
        # Block until TCP-level timeout (no user timeout)
        actions = [{{:timeout, :rto}, @initial_rto_ms, {:syn_timeout, from}}]
        {:next_state, {:syn_sent, from}, base_state, actions}

      ms when is_integer(ms) ->
        # Block with user-specified timeout
        actions = [
          {{:timeout, :rto}, @initial_rto_ms, {:syn_timeout, from}},
          {{:timeout, :connect_timeout}, ms, {:connect_timeout, from}}
        ]

        {:next_state, {:syn_sent, from}, base_state, actions}
    end
  end

  # SYN-ACK handler for blocking connect (from is a gen_statem from tuple)
  def handle_event(:info, segment, {:syn_sent, from}, %__MODULE__{} = state)
      when is_tuple(from) and is_binary(segment) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: seq, ack: ack, window: window, options: options} ->
        syn? = :syn in flags
        ack? = :ack in flags
        rst? = :rst in flags

        cond do
          rst? ->
            reset_state(state)

            actions = [
              {{:timeout, :rto}, :cancel},
              {{:timeout, :connect_timeout}, :cancel},
              {:reply, from, {:error, :econnrefused}}
            ]

            {:next_state, :closed, nil, actions}

          syn? and ack? and ack == state.iss + 1 ->
            # Valid SYN-ACK: send ACK and transition to ESTABLISHED
            send_ack(seq + 1, state)

            # Extract peer's MSS from options, default to 1220 (IPv6 min MTU 1280 - 60) if not present
            snd_mss = Map.get(options, :mss, @default_mss)

            new_state = %{
              state
              | irs: seq,
                rcv_nxt: seq + 1,
                snd_una: ack,
                snd_wnd: window,
                snd_mss: snd_mss,
                syn_retransmit_count: 0,
                rto_ms: @initial_rto_ms
            }

            # Cancel timers and reply success
            actions = [
              {{:timeout, :rto}, :cancel},
              {{:timeout, :connect_timeout}, :cancel},
              {:reply, from, :ok}
            ]

            {:next_state, :established, new_state, actions}

          ack? and ack != state.iss + 1 ->
            # Bad ACK: send RST
            send_rst(ack, state)
            :keep_state_and_data

          true ->
            # Ignore anything else
            :keep_state_and_data
        end

      _ ->
        :keep_state_and_data
    end
  end

  # SYN-ACK handler for :nowait connect
  def handle_event(:info, segment, {:syn_sent, :nowait}, %__MODULE__{} = state)
      when is_binary(segment) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: seq, ack: ack, window: window, options: options} ->
        syn? = :syn in flags
        ack? = :ack in flags
        rst? = :rst in flags

        cond do
          rst? ->
            # Connection refused - notify caller so a retry can complete with the stored error.
            actions = [{{:timeout, :rto}, :cancel}]
            {state_name, state_data} = nowait_connect_failure(state, :econnrefused)
            {:next_state, state_name, state_data, actions}

          syn? and ack? and ack == state.iss + 1 ->
            # Valid SYN-ACK: send ACK, notify caller, transition to ESTABLISHED
            send_ack(seq + 1, state)

            snd_mss = Map.get(options, :mss, @default_mss)

            # Notify callers that connect can complete
            notify_selects(state.connect_selects)

            new_state = %{
              state
              | irs: seq,
                rcv_nxt: seq + 1,
                snd_una: ack,
                snd_wnd: window,
                snd_mss: snd_mss,
                syn_retransmit_count: 0,
                rto_ms: @initial_rto_ms
            }

            actions = [{{:timeout, :rto}, :cancel}]
            {:next_state, :established, new_state, actions}

          ack? and ack != state.iss + 1 ->
            send_rst(ack, state)
            :keep_state_and_data

          true ->
            :keep_state_and_data
        end

      _ ->
        :keep_state_and_data
    end
  end

  # --- SYN retransmission timeout (blocking connect) ---

  def handle_event(
        {:timeout, :rto},
        {:syn_timeout, from},
        {:syn_sent, from},
        %__MODULE__{} = state
      ) do
    if state.syn_retransmit_count >= @max_retransmit_count do
      # Max retries exceeded - connection failure
      reset_state(state)
      actions = [{{:timeout, :connect_timeout}, :cancel}, {:reply, from, {:error, :etimedout}}]
      {:next_state, :closed, nil, actions}
    else
      retransmit_syn(state, {:syn_timeout, from})
    end
  end

  # --- SYN retransmission timeout (:nowait connect) ---

  def handle_event(
        {:timeout, :rto},
        :syn_timeout_nowait,
        {:syn_sent, :nowait},
        %__MODULE__{} = state
      ) do
    if state.syn_retransmit_count >= @max_retransmit_count do
      # Max retries exceeded - notify caller so a retry can complete with the stored error.
      {state_name, state_data} = nowait_connect_failure(state, :etimedout)
      {:next_state, state_name, state_data}
    else
      retransmit_syn(state, :syn_timeout_nowait)
    end
  end

  # --- User-level connect timeout (blocking only) ---

  def handle_event(
        {:timeout, :connect_timeout},
        {:connect_timeout, from},
        {:syn_sent, from},
        %__MODULE__{} = state
      ) do
    reset_state(state)
    actions = [{{:timeout, :rto}, :cancel}, {:reply, from, {:error, :timeout}}]
    {:next_state, :closed, nil, actions}
  end

  # --- Calls while connect is pending ---

  def handle_event({:call, from}, {:send, _data, _timeout}, {:syn_sent, _}, %__MODULE__{}) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  def handle_event({:call, from}, {:recv, _length, _timeout}, {:syn_sent, _}, %__MODULE__{}) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  def handle_event({:call, from}, :close, {:syn_sent, _}, %__MODULE__{}) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  def handle_event({:call, from}, {:shutdown, _how}, {:syn_sent, _}, %__MODULE__{}) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  # --- Send in invalid states ---

  # Not connected
  def handle_event({:call, from}, {:send, _data, _timeout}, :closed, _state_data) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  # Connection closing - can't send after initiating close
  def handle_event({:call, from}, {:send, _data, _timeout}, state_name, %__MODULE__{})
      when state_name in [:fin_wait_1, :fin_wait_2, :closing, :last_ack, :time_wait] do
    {:keep_state_and_data, {:reply, from, {:error, :epipe}}}
  end

  # --- Established state: send ---

  def handle_event(
        {:call, from},
        {:send, _data, _timeout},
        :established,
        %__MODULE__{write_shutdown: true}
      ) do
    {:keep_state_and_data, {:reply, from, {:error, :epipe}}}
  end

  def handle_event({:call, from}, {:send, data, timeout}, :established, %__MODULE__{} = state) do
    available = send_window_available(state)

    cond do
      available > 0 ->
        # Window available, enqueue data and return immediately
        new_state = %{state | send_buffer: DataBuffer.append(state.send_buffer, data)}
        {new_state, actions} = sync_persist_timer(new_state, [{:reply, from, :ok}])

        {:keep_state, new_state, actions ++ [{:next_event, :internal, :flush_send_buffer}]}

      timeout == :nowait ->
        # Window exhausted, return select tuple
        ref = make_ref()
        {caller_pid, _} = from
        waiter = {caller_pid, ref}
        new_state = %{state | send_waiters: state.send_waiters ++ [waiter]}
        {:keep_state, new_state, {:reply, from, {:select, {:select_info, :send, ref}}}}

      timeout == :infinity ->
        # Block until window opens
        ref = make_ref()
        waiter = {from, ref, data, nil}
        new_state = %{state | send_waiters: state.send_waiters ++ [waiter]}
        {new_state, actions} = sync_persist_timer(new_state, [])
        {:keep_state, new_state, actions}

      is_integer(timeout) ->
        # Block with timeout
        ref = make_ref()
        timer_ref = make_ref()
        waiter = {from, ref, data, timer_ref}
        new_state = %{state | send_waiters: state.send_waiters ++ [waiter]}

        {new_state, actions} =
          sync_persist_timer(new_state, [
            {{:timeout, timer_ref}, timeout, {:send_timeout, timer_ref}}
          ])

        {:keep_state, new_state, actions}
    end
  end

  # Handle send timeout
  def handle_event(
        {:timeout, timer_ref},
        {:send_timeout, timer_ref},
        :established,
        %__MODULE__{} = state
      ) do
    case List.keytake(state.send_waiters, timer_ref, 3) do
      {{from, _ref, _data, ^timer_ref}, rest} ->
        new_state = %{state | send_waiters: rest}
        {new_state, actions} = sync_persist_timer(new_state, [{:reply, from, {:error, :timeout}}])
        {:keep_state, new_state, actions}

      nil ->
        # Already fulfilled, ignore
        :keep_state_and_data
    end
  end

  def handle_event(:internal, :flush_send_buffer, :established, %__MODULE__{} = state) do
    cond do
      not DataBuffer.empty?(state.send_buffer) ->
        do_flush_send_buffer(state)

      state.write_shutdown ->
        {:keep_state, state, {:next_event, :internal, :send_pending_fin}}

      true ->
        :keep_state_and_data
    end
  end

  def handle_event(:internal, :send_pending_fin, :established, %__MODULE__{} = state) do
    send_pending_fin(state, :fin_wait_1)
  end

  # --- Established state: recv ---

  def handle_event({:call, from}, {:recv, length, timeout}, :established, %__MODULE__{} = state) do
    case deliver_data(state.recv_buffer, length) do
      {:ok, data, rest} ->
        new_state =
          state
          |> Map.put(:recv_buffer, rest)
          |> refresh_receive_window()
          |> maybe_send_window_update(state)

        {:keep_state, new_state, {:reply, from, {:ok, data}}}

      :wait ->
        # If read is shutdown and no data buffered, return closed
        if state.read_shutdown do
          {:keep_state_and_data, {:reply, from, {:error, :closed}}}
        else
          case timeout do
            :nowait ->
              # Return select tuple immediately, store caller info for notification
              ref = make_ref()
              {caller_pid, _} = from

              new_state = %{
                state
                | recv_selects: state.recv_selects ++ [{caller_pid, ref, length}]
              }

              {:keep_state, new_state, {:reply, from, {:select, {:select_info, :recv, ref}}}}

            :infinity ->
              # Block indefinitely
              timer_ref = make_ref()
              waiter = {from, length, timer_ref}
              new_state = %{state | recv_waiters: state.recv_waiters ++ [waiter]}
              {:keep_state, new_state}

            ms when is_integer(ms) ->
              # Block with timeout
              timer_ref = make_ref()
              waiter = {from, length, timer_ref}
              new_state = %{state | recv_waiters: state.recv_waiters ++ [waiter]}
              actions = [{{:timeout, timer_ref}, ms, {:recv_timeout, timer_ref}}]
              {:keep_state, new_state, actions}
          end
        end
    end
  end

  # Handle recv timeout
  def handle_event(
        {:timeout, timer_ref},
        {:recv_timeout, timer_ref},
        :established,
        %__MODULE__{} = state
      ) do
    case List.keytake(state.recv_waiters, timer_ref, 2) do
      {{from, _length, ^timer_ref}, rest} ->
        new_state = %{state | recv_waiters: rest}
        {:keep_state, new_state, {:reply, from, {:error, :timeout}}}

      nil ->
        # Already fulfilled, ignore
        :keep_state_and_data
    end
  end

  # --- Established state: incoming data ---

  def handle_event(:info, segment, :established, %__MODULE__{} = state) when is_binary(segment) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: seq, ack: ack, payload: payload, window: window} ->
        rst? = :rst in flags
        ack? = :ack in flags
        fin? = :fin in flags

        cond do
          rst? and acceptable_rst?(state, seq) ->
            reset_state(state)
            actions = notify_waiters_error(state, :econnreset)
            {:next_state, :closed, nil, actions}

          rst? ->
            reject_unacceptable_rst(state)

          invalid_ack?(state, ack?, ack) ->
            reject_invalid_ack(state)

          fin? and seq == state.rcv_nxt ->
            # FIN from peer - handle any data with it, then transition to CLOSE_WAIT
            data_len = byte_size(payload)
            {receive_state, accepted_len} = receive_payload(state, payload)

            new_snd_una =
              if ack? and seq_gt(ack, state.snd_una) and seq_leq(ack, state.snd_nxt) do
                ack
              else
                state.snd_una
              end

            if accepted_len == data_len do
              # Send ACK for FIN (and any data) after waiters consume buffered bytes.
              fin_state = %{receive_state | rcv_nxt: wrap_seq(receive_state.rcv_nxt + 1)}

              receive_state =
                fin_state
                |> notify_recv_select(:eof)
                |> Map.put(:snd_una, new_snd_una)
                |> Map.put(:snd_wnd, window)

              # Notify waiters: deliver buffered data or EOF
              {new_recv_buffer, new_waiters, replies} =
                process_waiters_eof(receive_state.recv_buffer, receive_state.recv_waiters)

              new_state =
                receive_state
                |> Map.put(:recv_buffer, new_recv_buffer)
                |> Map.put(:recv_waiters, new_waiters)
                |> Map.put(:fin_received, true)
                |> refresh_receive_window()

              send_ack(new_state.rcv_nxt, new_state)

              {:next_state, :close_wait, new_state, replies}
            else
              receive_state = notify_recv_select(receive_state, accepted_len)

              {new_recv_buffer, new_waiters, replies} =
                process_waiters(receive_state.recv_buffer, receive_state.recv_waiters)

              receive_state =
                receive_state
                |> Map.put(:recv_buffer, new_recv_buffer)
                |> Map.put(:recv_waiters, new_waiters)
                |> refresh_receive_window()

              {new_state, timer_actions} =
                if ack? do
                  process_ack(receive_state, ack, window)
                else
                  {%{receive_state | snd_wnd: window}, []}
                end

              send_ack(new_state.rcv_nxt, new_state)

              {:keep_state, new_state, replies ++ timer_actions}
            end

          ack? and seq == state.rcv_nxt and byte_size(payload) > 0 ->
            # Data segment with expected sequence number
            {receive_state, accepted_len} = receive_payload(state, payload)
            receive_state = notify_recv_select(receive_state, accepted_len)

            # Check if any blocking waiters can be satisfied
            {new_recv_buffer, new_waiters, replies} =
              process_waiters(receive_state.recv_buffer, receive_state.recv_waiters)

            # Process ACK portion to update retransmission queue
            receive_state =
              receive_state
              |> Map.put(:recv_buffer, new_recv_buffer)
              |> Map.put(:recv_waiters, new_waiters)
              |> refresh_receive_window()

            {new_state, timer_actions} = process_ack(receive_state, ack, window)
            send_ack(new_state.rcv_nxt, new_state)

            {:keep_state, new_state, replies ++ timer_actions}

          ack? and byte_size(payload) == 0 ->
            # Pure ACK - process ACK and update retransmission queue
            {new_state, timer_actions} = process_ack(state, ack, window)
            {:keep_state, new_state, timer_actions}

          byte_size(payload) > 0 or fin? ->
            ack_unacceptable_segment(state, ack?, ack, window)

          true ->
            :keep_state_and_data
        end

      _ ->
        :keep_state_and_data
    end
  end

  # --- Data retransmission timeout ---

  def handle_event({:timeout, :rto}, :retransmit, :established, %__MODULE__{} = state) do
    do_retransmit(state)
  end

  def handle_event({:timeout, :rto}, :retransmit, :close_wait, %__MODULE__{} = state) do
    do_retransmit(state)
  end

  def handle_event({:timeout, :rto}, :retransmit, :fin_wait_1, %__MODULE__{} = state) do
    do_retransmit(state)
  end

  def handle_event({:timeout, :rto}, :retransmit, :closing, %__MODULE__{} = state) do
    do_retransmit(state)
  end

  def handle_event({:timeout, :rto}, :retransmit, :last_ack, %__MODULE__{} = state) do
    do_retransmit(state)
  end

  def handle_event({:timeout, :persist}, :persist_probe, state_name, %__MODULE__{} = state)
      when state_name in [:established, :close_wait] do
    state = %{state | persist_timer_active: false}

    if persist_needed?(state) do
      send_zero_window_probe(state)

      next_timeout = min(state.persist_timeout_ms * 2, @max_persist_timeout_ms)

      new_state = %{
        state
        | persist_timer_active: true,
          persist_timeout_ms: next_timeout
      }

      {:keep_state, new_state, {{:timeout, :persist}, next_timeout, :persist_probe}}
    else
      {:keep_state, %{state | persist_timeout_ms: @initial_persist_timeout_ms}}
    end
  end

  def handle_event({:timeout, :persist}, :persist_probe, _state_name, _state_data) do
    :keep_state_and_data
  end

  def handle_event(
        :info,
        {:icmpv6_error, {:packet_too_big, mtu}},
        state_name,
        %__MODULE__{} = state
      )
      when state_name in [:established, :close_wait] do
    {new_state, actions} = apply_path_mtu(state, mtu)
    {:keep_state, new_state, actions}
  end

  def handle_event(
        :info,
        {:icmpv6_error, {:packet_too_big, mtu}},
        state_name,
        %__MODULE__{} = state
      )
      when state_name in [:fin_wait_1, :fin_wait_2, :closing, :last_ack] do
    {new_state, _actions} = apply_path_mtu(state, mtu)
    {:keep_state, new_state}
  end

  def handle_event(
        :info,
        {:icmpv6_error, {:hard, reason}},
        {:syn_sent, from},
        %__MODULE__{} = state
      )
      when is_tuple(from) do
    reset_state(state)

    actions = [
      {{:timeout, :rto}, :cancel},
      {{:timeout, :connect_timeout}, :cancel},
      {:reply, from, {:error, reason}}
    ]

    {:next_state, :closed, nil, actions}
  end

  def handle_event(
        :info,
        {:icmpv6_error, {:hard, reason}},
        {:syn_sent, :nowait},
        %__MODULE__{} = state
      ) do
    {state_name, state_data} = nowait_connect_failure(state, reason)
    {:next_state, state_name, state_data, {{:timeout, :rto}, :cancel}}
  end

  def handle_event(
        :info,
        {:icmpv6_error, {:hard, reason}},
        state_name,
        %__MODULE__{} = state
      )
      when state_name in [
             :established,
             :close_wait,
             :fin_wait_1,
             :fin_wait_2,
             :closing,
             :last_ack
           ] do
    reset_state(state)
    actions = notify_waiters_error(state, reason)
    {:next_state, :closed, nil, actions}
  end

  # --- Active close from established ---

  def handle_event(
        {:call, from},
        :close,
        :established,
        %__MODULE__{write_shutdown: true} = state
      ) do
    {:keep_state, state, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, :close, :established, %__MODULE__{} = state) do
    close_or_drain_send_buffer(state, from, :fin_wait_1)
  end

  # --- Shutdown from established ---

  # shutdown(:write) - send FIN, transition to fin_wait_1
  def handle_event(
        {:call, from},
        {:shutdown, :write},
        :established,
        %__MODULE__{write_shutdown: true} = state
      ) do
    {:keep_state, state, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, {:shutdown, :write}, :established, %__MODULE__{} = state) do
    close_or_drain_send_buffer(state, from, :fin_wait_1)
  end

  # shutdown(:read) - just mark read as shutdown, stay in established
  def handle_event({:call, from}, {:shutdown, :read}, :established, %__MODULE__{} = state) do
    new_state = %{state | read_shutdown: true}
    {:keep_state, new_state, {:reply, from, :ok}}
  end

  # shutdown(:read_write) - same as close
  def handle_event(
        {:call, from},
        {:shutdown, :read_write},
        :established,
        %__MODULE__{write_shutdown: true} = state
      ) do
    new_state = %{state | read_shutdown: true}
    {:keep_state, new_state, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, {:shutdown, :read_write}, :established, %__MODULE__{} = state) do
    state
    |> Map.put(:read_shutdown, true)
    |> close_or_drain_send_buffer(from, :fin_wait_1)
  end

  # --- FIN_WAIT_1 state ---

  def handle_event(:info, segment, :fin_wait_1, %__MODULE__{} = state) when is_binary(segment) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: seq, ack: ack, window: window} ->
        fin? = :fin in flags
        ack? = :ack in flags
        rst? = :rst in flags
        ack_of_fin? = ack? and ack == state.snd_nxt

        {ack_state, ack_actions} =
          if rst?, do: {state, []}, else: process_ack_if_present(state, ack?, ack, window)

        cond do
          rst? and acceptable_rst?(state, seq) ->
            reset_state(state)
            {:next_state, :closed, nil, {{:timeout, :rto}, :cancel}}

          rst? ->
            reject_unacceptable_rst(state)

          fin? and ack_of_fin? ->
            # FIN+ACK of our FIN - go directly to TIME_WAIT
            new_rcv_nxt = wrap_seq(seq + 1)
            new_state = %{ack_state | rcv_nxt: new_rcv_nxt, fin_received: true}
            send_ack(new_rcv_nxt, new_state)

            {:next_state, :time_wait, new_state,
             ack_actions ++ [{{:timeout, :time_wait}, @time_wait_ms, :time_wait_expired}]}

          fin? ->
            # FIN but not ACK of our FIN - simultaneous close
            new_rcv_nxt = wrap_seq(seq + 1)
            new_state = %{ack_state | rcv_nxt: new_rcv_nxt, fin_received: true}
            send_ack(new_rcv_nxt, new_state)
            {:next_state, :closing, new_state, ack_actions}

          ack_of_fin? ->
            # ACK of our FIN - move to FIN_WAIT_2
            {:next_state, :fin_wait_2, ack_state,
             ack_actions ++
               [
                 {{:timeout, :fin_wait_2}, ack_state.fin_wait_2_timeout_ms, :fin_wait_2_expired}
               ]}

          ack? ->
            {:keep_state, ack_state, ack_actions}

          true ->
            :keep_state_and_data
        end

      _ ->
        :keep_state_and_data
    end
  end

  # --- FIN_WAIT_2 state ---

  def handle_event(
        {:timeout, :fin_wait_2},
        :fin_wait_2_expired,
        :fin_wait_2,
        %__MODULE__{} = state
      ) do
    reset_state(state)
    {:next_state, :closed, nil}
  end

  def handle_event(:info, segment, :fin_wait_2, %__MODULE__{} = state) when is_binary(segment) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: seq, ack: ack, payload: payload, window: window} ->
        fin? = :fin in flags
        ack? = :ack in flags
        rst? = :rst in flags

        cond do
          rst? and acceptable_rst?(state, seq) ->
            reset_state(state)
            {:next_state, :closed, nil, {{:timeout, :fin_wait_2}, :cancel}}

          rst? ->
            reject_unacceptable_rst(state)

          invalid_ack?(state, ack?, ack) ->
            reject_invalid_ack(state)

          fin? and seq == state.rcv_nxt ->
            # FIN from peer - ACK it and go to TIME_WAIT
            # Handle any data that came with the FIN
            data_len = byte_size(payload)
            {receive_state, accepted_len} = receive_payload(%{state | snd_wnd: window}, payload)

            if accepted_len == data_len do
              new_state =
                receive_state
                |> Map.put(:rcv_nxt, wrap_seq(receive_state.rcv_nxt + 1))
                |> Map.put(:fin_received, true)
                |> refresh_receive_window()

              send_ack(new_state.rcv_nxt, new_state)

              {:next_state, :time_wait, new_state,
               [
                 {{:timeout, :fin_wait_2}, :cancel},
                 {{:timeout, :time_wait}, @time_wait_ms, :time_wait_expired}
               ]}
            else
              send_ack(receive_state.rcv_nxt, receive_state)
              {:keep_state, receive_state}
            end

          ack? and seq == state.rcv_nxt and byte_size(payload) > 0 ->
            # Data segment - half-close allows peer to still send data
            {new_state, _accepted_len} = receive_payload(%{state | snd_wnd: window}, payload)
            send_ack(new_state.rcv_nxt, new_state)

            {:keep_state, new_state}

          byte_size(payload) > 0 or fin? ->
            ack_unacceptable_segment(state, ack?, ack, window)

          true ->
            :keep_state_and_data
        end

      _ ->
        :keep_state_and_data
    end
  end

  # --- TIME_WAIT state ---

  def handle_event({:timeout, :time_wait}, :time_wait_expired, :time_wait, %__MODULE__{} = state) do
    reset_state(state)
    {:next_state, :closed, nil}
  end

  def handle_event(:info, segment, :time_wait, %__MODULE__{} = state) when is_binary(segment) do
    # Re-ACK any FIN received (peer may have missed our ACK)
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: _seq} ->
        if :fin in flags do
          send_ack(state.rcv_nxt, state)
        end

        :keep_state_and_data

      _ ->
        :keep_state_and_data
    end
  end

  # --- CLOSING state (simultaneous close) ---

  def handle_event(:info, segment, :closing, %__MODULE__{} = state) when is_binary(segment) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: seq, ack: ack, window: window} ->
        ack? = :ack in flags
        rst? = :rst in flags
        ack_of_fin? = ack? and ack == state.snd_nxt

        {ack_state, ack_actions} =
          if rst?, do: {state, []}, else: process_ack_if_present(state, ack?, ack, window)

        cond do
          rst? and acceptable_rst?(state, seq) ->
            reset_state(state)
            {:next_state, :closed, nil, {{:timeout, :rto}, :cancel}}

          rst? ->
            reject_unacceptable_rst(state)

          ack_of_fin? ->
            # ACK of our FIN - go to TIME_WAIT
            {:next_state, :time_wait, ack_state,
             ack_actions ++ [{{:timeout, :time_wait}, @time_wait_ms, :time_wait_expired}]}

          ack? ->
            {:keep_state, ack_state, ack_actions}

          true ->
            :keep_state_and_data
        end

      _ ->
        :keep_state_and_data
    end
  end

  # --- CLOSE_WAIT state (peer closed, we can still send) ---

  def handle_event(
        {:call, from},
        {:send, _data, _timeout},
        :close_wait,
        %__MODULE__{write_shutdown: true}
      ) do
    {:keep_state_and_data, {:reply, from, {:error, :epipe}}}
  end

  def handle_event({:call, from}, {:send, data, timeout}, :close_wait, %__MODULE__{} = state) do
    available = send_window_available(state)

    cond do
      available > 0 ->
        # Window available, enqueue data and return immediately
        new_state = %{state | send_buffer: DataBuffer.append(state.send_buffer, data)}
        {new_state, actions} = sync_persist_timer(new_state, [{:reply, from, :ok}])

        {:keep_state, new_state, actions ++ [{:next_event, :internal, :flush_send_buffer}]}

      timeout == :nowait ->
        # Window exhausted, return select tuple
        ref = make_ref()
        {caller_pid, _} = from
        waiter = {caller_pid, ref}
        new_state = %{state | send_waiters: state.send_waiters ++ [waiter]}
        {:keep_state, new_state, {:reply, from, {:select, {:select_info, :send, ref}}}}

      timeout == :infinity ->
        # Block until window opens
        ref = make_ref()
        waiter = {from, ref, data, nil}
        new_state = %{state | send_waiters: state.send_waiters ++ [waiter]}
        {new_state, actions} = sync_persist_timer(new_state, [])
        {:keep_state, new_state, actions}

      is_integer(timeout) ->
        # Block with timeout
        ref = make_ref()
        timer_ref = make_ref()
        waiter = {from, ref, data, timer_ref}
        new_state = %{state | send_waiters: state.send_waiters ++ [waiter]}

        {new_state, actions} =
          sync_persist_timer(new_state, [
            {{:timeout, timer_ref}, timeout, {:send_timeout, timer_ref}}
          ])

        {:keep_state, new_state, actions}
    end
  end

  def handle_event(:internal, :flush_send_buffer, :close_wait, %__MODULE__{} = state) do
    cond do
      not DataBuffer.empty?(state.send_buffer) ->
        do_flush_send_buffer(state)

      state.write_shutdown ->
        {:keep_state, state, {:next_event, :internal, :send_pending_fin}}

      true ->
        :keep_state_and_data
    end
  end

  def handle_event(:internal, :send_pending_fin, :close_wait, %__MODULE__{} = state) do
    send_pending_fin(state, :last_ack)
  end

  # Handle send timeout in close_wait
  def handle_event(
        {:timeout, timer_ref},
        {:send_timeout, timer_ref},
        :close_wait,
        %__MODULE__{} = state
      ) do
    case List.keytake(state.send_waiters, timer_ref, 3) do
      {{from, _ref, _data, ^timer_ref}, rest} ->
        new_state = %{state | send_waiters: rest}
        {new_state, actions} = sync_persist_timer(new_state, [{:reply, from, {:error, :timeout}}])
        {:keep_state, new_state, actions}

      nil ->
        # Already fulfilled, ignore
        :keep_state_and_data
    end
  end

  def handle_event({:call, from}, {:recv, length, _timeout}, :close_wait, %__MODULE__{} = state) do
    case deliver_data(state.recv_buffer, length) do
      {:ok, data, rest} ->
        new_state =
          state
          |> Map.put(:recv_buffer, rest)
          |> refresh_receive_window()
          |> maybe_send_window_update(state)

        {:keep_state, new_state, {:reply, from, {:ok, data}}}

      :wait ->
        # No data and peer already sent FIN - return EOF
        {:keep_state_and_data, {:reply, from, {:ok, <<>>}}}
    end
  end

  def handle_event({:call, from}, :close, :close_wait, %__MODULE__{write_shutdown: true} = state) do
    {:keep_state, state, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, :close, :close_wait, %__MODULE__{} = state) do
    close_or_drain_send_buffer(state, from, :last_ack)
  end

  # shutdown(:write) in close_wait - send FIN, go to last_ack
  def handle_event(
        {:call, from},
        {:shutdown, :write},
        :close_wait,
        %__MODULE__{write_shutdown: true} = state
      ) do
    {:keep_state, state, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, {:shutdown, :write}, :close_wait, %__MODULE__{} = state) do
    close_or_drain_send_buffer(state, from, :last_ack)
  end

  # shutdown(:read) in close_wait - already received FIN, just mark it
  def handle_event({:call, from}, {:shutdown, :read}, :close_wait, %__MODULE__{} = state) do
    new_state = %{state | read_shutdown: true}
    {:keep_state, new_state, {:reply, from, :ok}}
  end

  # shutdown(:read_write) in close_wait - send FIN, go to last_ack
  def handle_event(
        {:call, from},
        {:shutdown, :read_write},
        :close_wait,
        %__MODULE__{write_shutdown: true} = state
      ) do
    new_state = %{state | read_shutdown: true}
    {:keep_state, new_state, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, {:shutdown, :read_write}, :close_wait, %__MODULE__{} = state) do
    state
    |> Map.put(:read_shutdown, true)
    |> close_or_drain_send_buffer(from, :last_ack)
  end

  def handle_event(:info, segment, :close_wait, %__MODULE__{} = state) when is_binary(segment) do
    # Handle ACKs for data we sent
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: seq, ack: ack, window: window} ->
        rst? = :rst in flags
        ack? = :ack in flags

        cond do
          rst? and acceptable_rst?(state, seq) ->
            reset_state(state)
            actions = notify_waiters_error(state, :econnreset)
            {:next_state, :closed, nil, actions}

          rst? ->
            reject_unacceptable_rst(state)

          ack? ->
            # Process ACK and update retransmission queue
            {new_state, timer_actions} = process_ack(state, ack, window)
            {:keep_state, new_state, timer_actions}

          true ->
            :keep_state_and_data
        end

      _ ->
        :keep_state_and_data
    end
  end

  # --- LAST_ACK state ---

  def handle_event(:info, segment, :last_ack, %__MODULE__{} = state) when is_binary(segment) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: seq, ack: ack, window: window} ->
        rst? = :rst in flags
        ack? = :ack in flags
        ack_of_fin? = ack? and ack == state.snd_nxt

        {ack_state, ack_actions} =
          if rst?, do: {state, []}, else: process_ack_if_present(state, ack?, ack, window)

        cond do
          rst? and acceptable_rst?(state, seq) ->
            reset_state(state)
            {:next_state, :closed, nil, {{:timeout, :rto}, :cancel}}

          rst? ->
            reject_unacceptable_rst(state)

          ack_of_fin? ->
            # ACK of our FIN - connection fully closed
            reset_state(ack_state)
            {:next_state, :closed, nil, ack_actions}

          ack? ->
            {:keep_state, ack_state, ack_actions}

          true ->
            :keep_state_and_data
        end

      _ ->
        :keep_state_and_data
    end
  end

  # --- Catch-all handlers ---

  # Send/recv on non-established socket
  def handle_event({:call, from}, {:send, _data, _timeout}, _state, _state_data) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  def handle_event({:call, from}, {:recv, _length, _timeout}, _state, _state_data) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  def handle_event({:call, from}, :close, _state, _state_data) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  # Catch-all shutdown handler for invalid states
  def handle_event({:call, from}, {:shutdown, _how}, _state, _state_data) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  defp retransmit_syn(state, timeout_event) do
    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(state.pair, state.iss, 0, [:syn], receive_window(state),
        mss: state.rcv_mss
      )

    packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
    :ok = Tricep.Link.send(state.link, packet)

    # Exponential backoff
    new_rto = min(state.rto_ms * 2, @max_rto_ms)
    new_state = %{state | syn_retransmit_count: state.syn_retransmit_count + 1, rto_ms: new_rto}

    actions = [{{:timeout, :rto}, new_rto, timeout_event}]
    {:keep_state, new_state, actions}
  end

  defp do_retransmit(%__MODULE__{unacked_segments: []} = state) do
    # Nothing to retransmit, clear timer state
    {:keep_state, %{state | rto_timer_active: false}}
  end

  defp do_retransmit(%__MODULE__{unacked_segments: [{seq, seq_end, :fin, count} | rest]} = state) do
    if count >= @max_retransmit_count do
      # Max retries exceeded - connection failure
      reset_state(state)
      actions = notify_waiters_error(state, :etimedout)
      {:next_state, :closed, nil, actions}
    else
      send_fin_segment(state, seq)

      # Update segment with incremented retransmit count
      updated_entry = {seq, seq_end, :fin, count + 1}
      new_unacked = [updated_entry | rest]

      # Exponential backoff
      new_rto = min(state.rto_ms * 2, @max_rto_ms)

      new_state = %{
        state
        | unacked_segments: new_unacked,
          rto_ms: new_rto,
          rto_timer_active: true
      }

      # Schedule next RTO timer
      actions = [{{:timeout, :rto}, new_rto, :retransmit}]
      {:keep_state, new_state, actions}
    end
  end

  defp do_retransmit(
         %__MODULE__{unacked_segments: [{seq, _seq_end, payload, count} | rest]} = state
       )
       when is_binary(payload) do
    if count >= @max_retransmit_count do
      # Max retries exceeded - connection failure
      reset_state(state)
      actions = notify_waiters_error(state, :etimedout)
      {:next_state, :closed, nil, actions}
    else
      # Retransmit the oldest unacked segment
      {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

      tcp_segment =
        Tcp.build_segment(
          state.pair,
          seq,
          state.rcv_nxt,
          [:ack, :psh],
          receive_window(state),
          payload: payload
        )

      packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
      Tricep.Link.send(state.link, packet)

      # Update segment with incremented retransmit count
      updated_entry = {seq, wrap_seq(seq + byte_size(payload)), payload, count + 1}
      new_unacked = [updated_entry | rest]

      # Exponential backoff
      new_rto = min(state.rto_ms * 2, @max_rto_ms)

      new_state = %{
        state
        | unacked_segments: new_unacked,
          rto_ms: new_rto,
          rto_timer_active: true
      }

      # Schedule next RTO timer
      actions = [{{:timeout, :rto}, new_rto, :retransmit}]
      {:keep_state, new_state, actions}
    end
  end

  defp notify_recv_waiters_error(waiters, error) do
    Enum.flat_map(waiters, fn {from, _length, timer_ref} ->
      [
        {:reply, from, {:error, error}},
        {{:timeout, timer_ref}, :cancel}
      ]
    end)
  end

  defp notify_send_waiters_error(waiters, error) do
    Enum.flat_map(waiters, fn
      {from, _ref, _data, timer_ref} when is_tuple(from) ->
        actions = [{:reply, from, {:error, error}}]

        if timer_ref do
          [{{:timeout, timer_ref}, :cancel} | actions]
        else
          actions
        end

      {caller_pid, ref} when is_pid(caller_pid) ->
        notify_select(caller_pid, ref)
        []
    end)
  end

  defp notify_waiters_error(%__MODULE__{} = state, error) do
    notify_selects(state.recv_selects)

    cancel_persist_timer_action(state) ++
      notify_recv_waiters_error(state.recv_waiters, error) ++
      notify_send_waiters_error(state.send_waiters, error)
  end

  defp do_flush_send_buffer(%__MODULE__{} = state) do
    available = send_window_available(state)

    cond do
      DataBuffer.empty?(state.send_buffer) ->
        keep_state_sync_persist(state)

      available <= 0 ->
        keep_state_sync_persist(state)

      true ->
        # Take only bytes the peer's advertised receive window currently permits.
        mss = state.snd_mss || @default_mss
        send_len = min(mss, available)
        {payload_iodata, new_send_buffer} = DataBuffer.take(state.send_buffer, send_len)
        payload = IO.iodata_to_binary(payload_iodata)

        seq_start = state.snd_nxt
        seq_end = wrap_seq(seq_start + byte_size(payload))

        {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

        tcp_segment =
          Tcp.build_segment(
            state.pair,
            seq_start,
            state.rcv_nxt,
            [:ack, :psh],
            receive_window(state),
            payload: payload
          )

        packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
        Tricep.Link.send(state.link, packet)

        # Track segment for retransmission: {seq_start, seq_end, payload, retransmit_count}
        unacked_entry = {seq_start, seq_end, payload, 0}
        new_unacked = state.unacked_segments ++ [unacked_entry]

        new_state = %{
          state
          | send_buffer: new_send_buffer,
            snd_nxt: seq_end,
            unacked_segments: new_unacked
        }

        actions =
          new_state
          |> schedule_flush_send_buffer([])
          |> schedule_pending_fin(new_state)

        {new_state, actions} = sync_persist_timer(new_state, actions)

        # Start RTO timer if not already running
        {new_state, actions} =
          if not state.rto_timer_active do
            {%{new_state | rto_timer_active: true},
             [{{:timeout, :rto}, state.rto_ms, :retransmit} | actions]}
          else
            {new_state, actions}
          end

        {:keep_state, new_state, actions}
    end
  end

  defp reset_state(%__MODULE__{} = state) do
    Application.deregister_socket_pair(state.pair)
  end

  defp nowait_connect_failure(%__MODULE__{} = state, reason) do
    reset_state(state)

    case state.connect_selects do
      [] ->
        {:closed, nil}

      connect_selects ->
        notify_selects(connect_selects)
        {{:connect_failed, connect_selects, reason}, nil}
    end
  end

  defp send_ack(ack_num, %__MODULE__{} = state) do
    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(state.pair, state.snd_nxt, ack_num, [:ack], receive_window(state))

    packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
    Tricep.Link.send(state.link, packet)
  end

  defp send_rst(seq_num, %__MODULE__{} = state) do
    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    tcp_segment = Tcp.build_segment(state.pair, seq_num, 0, [:rst], 0)

    packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
    Tricep.Link.send(state.link, packet)
  end

  defp send_fin_and_track(%__MODULE__{} = state) do
    seq_start = state.snd_nxt
    seq_end = wrap_seq(seq_start + 1)

    send_fin_segment(state, seq_start)

    new_state = %{
      state
      | snd_nxt: seq_end,
        unacked_segments: state.unacked_segments ++ [{seq_start, seq_end, :fin, 0}]
    }

    if state.rto_timer_active do
      {new_state, []}
    else
      {%{new_state | rto_timer_active: true}, [{{:timeout, :rto}, state.rto_ms, :retransmit}]}
    end
  end

  defp close_or_drain_send_buffer(%__MODULE__{} = state, from, next_state) do
    if DataBuffer.empty?(state.send_buffer) do
      {new_state, actions} = send_fin_and_track(%{state | write_shutdown: false})
      {:next_state, next_state, new_state, [{:reply, from, :ok} | actions]}
    else
      new_state = %{state | write_shutdown: true}

      {:keep_state, new_state,
       [{:reply, from, :ok}, {:next_event, :internal, :flush_send_buffer}]}
    end
  end

  defp send_pending_fin(%__MODULE__{} = state, next_state) do
    if DataBuffer.empty?(state.send_buffer) do
      {new_state, actions} = send_fin_and_track(%{state | write_shutdown: false})
      {:next_state, next_state, new_state, actions}
    else
      {:keep_state, state, {:next_event, :internal, :flush_send_buffer}}
    end
  end

  defp schedule_pending_fin(actions, %__MODULE__{write_shutdown: true} = state) do
    if DataBuffer.empty?(state.send_buffer) do
      actions ++ [{:next_event, :internal, :send_pending_fin}]
    else
      actions
    end
  end

  defp schedule_pending_fin(actions, %__MODULE__{}), do: actions

  defp send_fin_segment(%__MODULE__{} = state, seq) do
    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(
        state.pair,
        seq,
        state.rcv_nxt,
        [:fin, :ack],
        receive_window(state)
      )

    packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
    Tricep.Link.send(state.link, packet)
  end

  defp allocate_port(srcaddr_bin, dst) do
    state = :rand.seed_s(:default)
    allocate_port(srcaddr_bin, dst, state)
  end

  defp allocate_port(srcaddr_bin, dst, state) do
    {rand, state} = :rand.uniform_s(16384, state)
    port = 49151 + rand
    pair = {{srcaddr_bin, port}, dst}

    case Application.register_socket_pair(pair) do
      :ok ->
        pair

      _ ->
        allocate_port(srcaddr_bin, dst, state)
    end
  end

  # --- Helper functions ---

  defp validate_sockaddr_in6(%{family: :inet6, addr: addr, port: port}) do
    with true <- is_integer(port) and port in 1..65_535,
         {:ok, dstaddr_bin} <- valid_ipv6_address(addr) do
      {:ok, dstaddr_bin, port}
    else
      _ -> {:error, :einval}
    end
  end

  defp validate_sockaddr_in6(_address), do: {:error, :einval}

  defp valid_ipv6_address(addr) do
    Tricep.Address.from(addr)
  rescue
    FunctionClauseError -> {:error, :einval}
    ArgumentError -> {:error, :einval}
  end

  # Wrap sequence number at 32 bits
  defp wrap_seq(n), do: n &&& 0xFFFFFFFF

  # Sequence number comparison (handles 32-bit wrap-around)
  # Returns true if a > b in sequence space
  defp seq_gt(a, b) do
    diff = a - b &&& 0xFFFFFFFF
    diff > 0 and diff < 0x80000000
  end

  # Returns true if a <= b in sequence space
  defp seq_leq(a, b), do: not seq_gt(a, b)
  defp seq_lt(a, b), do: seq_gt(b, a)
  defp seq_geq(a, b), do: a == b or seq_gt(a, b)

  defp socket_opts(opts) when is_list(opts), do: Keyword.get(opts, :opts, %{})
  defp socket_opts(opts) when is_map(opts), do: opts
  defp socket_opts(_opts), do: %{}

  defp recv_buffer_size(%{socket_opts: opts}), do: configured_recv_buffer_size(opts)
  defp recv_buffer_size(_closed_data), do: @default_recv_buffer_size

  defp fin_wait_2_timeout_ms(%{socket_opts: opts}), do: configured_fin_wait_2_timeout_ms(opts)
  defp fin_wait_2_timeout_ms(_closed_data), do: @default_fin_wait_2_timeout_ms

  defp configured_recv_buffer_size(opts) when is_map(opts) do
    opts
    |> Map.get(:recv_buffer_size, Map.get(opts, :rcvbuf, @default_recv_buffer_size))
    |> normalize_recv_buffer_size()
  end

  defp configured_recv_buffer_size(opts) when is_list(opts) do
    opts
    |> Keyword.get(:recv_buffer_size, Keyword.get(opts, :rcvbuf, @default_recv_buffer_size))
    |> normalize_recv_buffer_size()
  end

  defp configured_recv_buffer_size(_opts), do: @default_recv_buffer_size

  defp configured_fin_wait_2_timeout_ms(opts) when is_map(opts) do
    opts
    |> Map.get(:fin_wait_2_timeout_ms, @default_fin_wait_2_timeout_ms)
    |> normalize_fin_wait_2_timeout_ms()
  end

  defp configured_fin_wait_2_timeout_ms(opts) when is_list(opts) do
    opts
    |> Keyword.get(:fin_wait_2_timeout_ms, @default_fin_wait_2_timeout_ms)
    |> normalize_fin_wait_2_timeout_ms()
  end

  defp configured_fin_wait_2_timeout_ms(_opts), do: @default_fin_wait_2_timeout_ms

  defp normalize_recv_buffer_size(size) when is_integer(size) and size > 0 do
    min(size, @max_tcp_window)
  end

  defp normalize_recv_buffer_size(_size), do: @default_recv_buffer_size

  defp normalize_fin_wait_2_timeout_ms(timeout_ms)
       when is_integer(timeout_ms) and timeout_ms > 0 do
    timeout_ms
  end

  defp normalize_fin_wait_2_timeout_ms(_timeout_ms), do: @default_fin_wait_2_timeout_ms

  defp receive_window(%__MODULE__{} = state) do
    state.recv_buffer
    |> byte_size()
    |> then(&max(0, state.recv_buffer_size - &1))
    |> min(@max_tcp_window)
  end

  defp refresh_receive_window(%__MODULE__{} = state) do
    %{state | rcv_wnd: receive_window(state)}
  end

  defp maybe_send_window_update(%__MODULE__{} = new_state, %__MODULE__{} = old_state) do
    if new_state.rcv_wnd > old_state.rcv_wnd do
      send_ack(new_state.rcv_nxt, new_state)
    end

    new_state
  end

  defp receive_payload(%__MODULE__{} = state, payload) do
    accepted_len = min(byte_size(payload), receive_window(state))
    {accepted_payload, _overflow} = split_binary(payload, accepted_len)

    new_state =
      state
      |> Map.put(:recv_buffer, state.recv_buffer <> accepted_payload)
      |> Map.put(:rcv_nxt, wrap_seq(state.rcv_nxt + accepted_len))
      |> refresh_receive_window()

    {new_state, accepted_len}
  end

  defp notify_recv_select(%__MODULE__{} = state, :eof) do
    notify_selects(state.recv_selects)
    %{state | recv_selects: []}
  end

  defp notify_recv_select(%__MODULE__{} = state, accepted_len) when accepted_len > 0 do
    notify_selects(state.recv_selects)
    %{state | recv_selects: []}
  end

  defp notify_recv_select(%__MODULE__{} = state, _accepted_len), do: state

  defp keep_state_sync_persist(state, actions \\ []) do
    {new_state, actions} = sync_persist_timer(state, actions)
    {:keep_state, new_state, actions}
  end

  defp sync_persist_timer(%__MODULE__{} = state, actions) do
    cond do
      persist_needed?(state) and state.persist_timer_active ->
        {state, actions}

      persist_needed?(state) ->
        {%{state | persist_timer_active: true},
         actions ++ [{{:timeout, :persist}, state.persist_timeout_ms, :persist_probe}]}

      state.persist_timer_active ->
        new_state = %{
          state
          | persist_timer_active: false,
            persist_timeout_ms: @initial_persist_timeout_ms
        }

        {new_state, actions ++ [{{:timeout, :persist}, :cancel}]}

      true ->
        {%{state | persist_timeout_ms: @initial_persist_timeout_ms}, actions}
    end
  end

  defp cancel_persist_timer_action(%__MODULE__{persist_timer_active: true}) do
    [{{:timeout, :persist}, :cancel}]
  end

  defp cancel_persist_timer_action(%__MODULE__{}), do: []

  defp persist_needed?(%__MODULE__{snd_wnd: 0} = state), do: has_persist_data?(state)
  defp persist_needed?(%__MODULE__{}), do: false

  defp has_persist_data?(%__MODULE__{} = state) do
    not DataBuffer.empty?(state.send_buffer) or has_blocking_send_waiter?(state.send_waiters)
  end

  defp has_blocking_send_waiter?(waiters) do
    Enum.any?(waiters, fn
      {from, _ref, data, _timer_ref} when is_tuple(from) -> byte_size(data) > 0
      _waiter -> false
    end)
  end

  defp send_zero_window_probe(%__MODULE__{} = state) do
    case persist_probe_payload(state) do
      nil ->
        :ok

      payload ->
        {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair
        seq = wrap_seq(state.snd_nxt - 1)

        tcp_segment =
          Tcp.build_segment(
            state.pair,
            seq,
            state.rcv_nxt,
            [:ack, :psh],
            receive_window(state),
            payload: payload
          )

        packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
        Tricep.Link.send(state.link, packet)
    end
  end

  defp persist_probe_payload(%__MODULE__{} = state) do
    case DataBuffer.take(state.send_buffer, 1) do
      {[], _buffer} -> blocking_send_waiter_probe_payload(state.send_waiters)
      {iodata, _buffer} -> IO.iodata_to_binary(iodata)
    end
  end

  defp blocking_send_waiter_probe_payload(waiters) do
    Enum.find_value(waiters, fn
      {from, _ref, data, _timer_ref} when is_tuple(from) and byte_size(data) > 0 ->
        binary_part(data, 0, 1)

      _waiter ->
        nil
    end)
  end

  defp apply_path_mtu(%__MODULE__{} = state, mtu) when is_integer(mtu) and mtu > 0 do
    new_mss = max(1, mtu - 60)
    current_mss = state.snd_mss || @default_mss

    if new_mss < current_mss do
      new_state = %{state | snd_mss: new_mss}
      actions = schedule_flush_send_buffer(new_state, [])
      {new_state, actions}
    else
      {state, []}
    end
  end

  defp apply_path_mtu(%__MODULE__{} = state, _mtu), do: {state, []}

  # Calculate available send window (for backpressure detection)
  defp send_window_available(state) do
    bytes_in_flight = wrap_seq(state.snd_nxt - state.snd_una)
    max(0, state.snd_wnd - bytes_in_flight)
  end

  # Send select notification to caller
  defp notify_select(caller_pid, ref) do
    send(caller_pid, {:"$socket", self(), :select, ref})
  end

  defp notify_selects(selects) do
    Enum.each(selects, fn
      {caller_pid, ref} -> notify_select(caller_pid, ref)
      {caller_pid, ref, _length} -> notify_select(caller_pid, ref)
    end)
  end

  # Process ACK and update retransmission queue
  # Returns {new_state, timer_actions}
  defp process_ack_if_present(state, false, _ack, window) do
    state
    |> Map.put(:snd_wnd, window)
    |> sync_persist_timer([])
  end

  defp process_ack_if_present(state, true, ack, window), do: process_ack(state, ack, window)

  defp invalid_ack?(state, true, ack), do: seq_gt(ack, state.snd_nxt)
  defp invalid_ack?(_state, false, _ack), do: false

  defp acceptable_rst?(state, seq) do
    seq_in_receive_window?(seq, state.rcv_nxt, receive_window(state))
  end

  defp seq_in_receive_window?(seq, rcv_nxt, 0), do: seq == rcv_nxt

  defp seq_in_receive_window?(seq, rcv_nxt, window) do
    window_end = wrap_seq(rcv_nxt + window)
    seq_geq(seq, rcv_nxt) and seq_lt(seq, window_end)
  end

  defp reject_invalid_ack(state) do
    send_ack(state.rcv_nxt, state)
    {:keep_state, state, []}
  end

  defp reject_unacceptable_rst(state) do
    send_ack(state.rcv_nxt, state)
    {:keep_state, state, []}
  end

  defp ack_unacceptable_segment(state, ack?, ack, window) do
    {new_state, actions} = process_ack_if_present(state, ack?, ack, window)
    send_ack(new_state.rcv_nxt, new_state)
    {:keep_state, new_state, actions}
  end

  defp process_ack(state, ack, window) do
    cond do
      seq_gt(ack, state.snd_nxt) ->
        send_ack(state.rcv_nxt, state)
        {state, []}

      seq_gt(ack, state.snd_una) ->
        # ACK acknowledges new data - remove acknowledged segments from queue
        new_unacked =
          Enum.drop_while(state.unacked_segments, fn {_seq_start, seq_end, _payload, _count} ->
            seq_leq(seq_end, ack)
          end)

        base_state = %{
          state
          | snd_una: ack,
            snd_wnd: window,
            unacked_segments: new_unacked,
            rto_ms: @initial_rto_ms
        }

        # Check if window opened and we have send_waiters
        {new_state, send_waiter_actions} = process_send_waiters(base_state)
        send_waiter_actions = schedule_flush_send_buffer(new_state, send_waiter_actions)

        # Manage RTO timer based on remaining unacked segments
        timer_actions =
          if new_unacked == [] do
            # All data acknowledged - cancel timer
            [{{:timeout, :rto}, :cancel}]
          else
            # More unacked data - restart timer with fresh RTO
            [{{:timeout, :rto}, @initial_rto_ms, :retransmit}]
          end

        new_state = %{new_state | rto_timer_active: new_unacked != []}
        sync_persist_timer(new_state, timer_actions ++ send_waiter_actions)

      true ->
        # Duplicate or old ACK - just update window (but still check send waiters)
        base_state = %{state | snd_wnd: window}
        {new_state, send_waiter_actions} = process_send_waiters(base_state)
        send_waiter_actions = schedule_flush_send_buffer(new_state, send_waiter_actions)
        sync_persist_timer(new_state, send_waiter_actions)
    end
  end

  defp schedule_flush_send_buffer(state, actions) do
    flush_action = {:next_event, :internal, :flush_send_buffer}

    if not DataBuffer.empty?(state.send_buffer) and send_window_available(state) > 0 and
         flush_action not in actions do
      actions ++ [flush_action]
    else
      actions
    end
  end

  # Process send_waiters when window opens.
  defp process_send_waiters(state) do
    capacity = send_waiter_capacity(state)
    process_send_waiters(state.send_waiters, %{state | send_waiters: []}, capacity, [])
  end

  defp process_send_waiters([], state, _capacity, actions) do
    {state, actions}
  end

  defp process_send_waiters(remaining_waiters, state, capacity, actions) when capacity <= 0 do
    {%{state | send_waiters: remaining_waiters}, actions}
  end

  defp process_send_waiters([{caller_pid, ref} | rest], state, capacity, actions)
       when is_pid(caller_pid) do
    # :nowait waiter - notify readiness; caller must retry send to enqueue data.
    notify_select(caller_pid, ref)
    process_send_waiters(rest, state, capacity, actions)
  end

  defp process_send_waiters([{from, _ref, data, timer_ref} | rest], state, capacity, actions)
       when is_tuple(from) do
    # Blocking waiter - enqueue data and reply.
    new_send_buffer = DataBuffer.append(state.send_buffer, data)
    new_state = %{state | send_buffer: new_send_buffer}
    cancel_actions = if timer_ref, do: [{{:timeout, timer_ref}, :cancel}], else: []
    waiter_actions = cancel_actions ++ [{:reply, from, :ok}]

    process_send_waiters(rest, new_state, capacity - byte_size(data), actions ++ waiter_actions)
  end

  defp send_waiter_capacity(state) do
    max(0, send_window_available(state) - DataBuffer.size(state.send_buffer))
  end

  defp take_select_for_pid(selects, caller_pid) do
    case Enum.split_while(selects, fn {select_pid, _ref} -> select_pid != caller_pid end) do
      {_prefix, []} ->
        nil

      {prefix, [select | rest]} ->
        {select, prefix ++ rest}
    end
  end

  # Split binary at position (or end if shorter)
  defp split_binary(bin, pos) when byte_size(bin) <= pos, do: {bin, <<>>}
  defp split_binary(bin, pos), do: :erlang.split_binary(bin, pos)

  # Check if we can deliver data for a recv call
  defp deliver_data(<<>>, _length), do: :wait
  defp deliver_data(buffer, 0), do: {:ok, buffer, <<>>}

  defp deliver_data(buffer, length) when byte_size(buffer) >= length do
    {data, rest} = split_binary(buffer, length)
    {:ok, data, rest}
  end

  defp deliver_data(_buffer, _length), do: :wait

  # Process recv waiters when new data arrives
  defp process_waiters(buffer, waiters) do
    process_waiters(buffer, waiters, [], [])
  end

  defp process_waiters(buffer, [], remaining_waiters, actions) do
    {buffer, Enum.reverse(remaining_waiters), Enum.reverse(actions)}
  end

  defp process_waiters(buffer, [{from, length, timer_ref} | rest], remaining_waiters, actions) do
    case deliver_data(buffer, length) do
      {:ok, data, new_buffer} ->
        # Reply and cancel the timeout
        new_actions = [
          {:reply, from, {:ok, data}},
          {{:timeout, timer_ref}, :cancel}
        ]

        process_waiters(new_buffer, rest, remaining_waiters, new_actions ++ actions)

      :wait ->
        # Can't satisfy this waiter, keep it
        process_waiters(buffer, rest, [{from, length, timer_ref} | remaining_waiters], actions)
    end
  end

  # Process recv waiters when FIN is received - deliver data or EOF
  defp process_waiters_eof(buffer, waiters) do
    process_waiters_eof(buffer, waiters, [], [])
  end

  defp process_waiters_eof(buffer, [], _remaining_waiters, actions) do
    # All waiters processed - no remaining waiters since we have EOF
    {buffer, [], Enum.reverse(actions)}
  end

  defp process_waiters_eof(buffer, [{from, length, timer_ref} | rest], remaining_waiters, actions) do
    case deliver_data(buffer, length) do
      {:ok, data, new_buffer} ->
        # Reply with data and cancel the timeout
        new_actions = [
          {:reply, from, {:ok, data}},
          {{:timeout, timer_ref}, :cancel}
        ]

        process_waiters_eof(new_buffer, rest, remaining_waiters, new_actions ++ actions)

      :wait ->
        # No data available - return EOF ({:ok, <<>>})
        new_actions = [
          {:reply, from, {:ok, <<>>}},
          {{:timeout, timer_ref}, :cancel}
        ]

        process_waiters_eof(buffer, rest, remaining_waiters, new_actions ++ actions)
    end
  end
end
