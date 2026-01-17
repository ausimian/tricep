defmodule Tricep.Socket do
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

  def handle_packet(src_addr, dst_addr, <<src_port::16, dst_port::16, _::binary>> = segment) do
    pair = {{dst_addr, dst_port}, {src_addr, src_port}}

    if pid = Application.lookup_socket_pair(pair) do
      send(pid, segment)
    end

    :ok
  end

  # Ignore malformed packets that are too short to parse
  def handle_packet(_src_addr, _dst_addr, _segment), do: :ok

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

  # Retransmission timeout constants
  @initial_rto_ms 1_000
  @max_rto_ms 60_000
  @max_retransmit_count 5

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
    # Callers waiting on recv (list of {from, length, timer_ref})
    field :recv_waiters, list(), default: []
    # Track if peer has sent FIN (EOF)
    field :fin_received, boolean(), default: false
    # Retransmission support: list of {seq_start, seq_end, payload, retransmit_count}
    field :unacked_segments, list(), default: []
    # Current RTO in milliseconds
    field :rto_ms, non_neg_integer(), default: 1_000
    # Whether the RTO timer is currently active
    field :rto_timer_active, boolean(), default: false
    # SYN retransmit count (for connection phase)
    field :syn_retransmit_count, non_neg_integer(), default: 0
    # For :nowait connect - {caller_pid, ref}
    field :connect_select, {pid(), reference()} | nil, default: nil
    # For :nowait recv - {caller_pid, ref, length}
    field :recv_select, {pid(), reference(), non_neg_integer()} | nil, default: nil
    # For send backpressure - [{caller_pid, ref, data} | {from, ref, data, timer_ref}]
    field :send_waiters, list(), default: []
  end

  # TIME_WAIT duration (2*MSL - using short value for TUN-based stack)
  @time_wait_ms 2_000

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init(_opts) do
    {:ok, :closed, nil}
  end

  @impl true
  def handle_event({:call, from}, {:connect, %{addr: addr} = address, timeout}, :closed, nil) do
    case Tricep.Address.from(addr) do
      {:ok, dstaddr_bin} ->
        case Application.lookup_link(dstaddr_bin) do
          {pid, {srcaddr_bin, mtu}} ->
            pair = allocate_port(srcaddr_bin, {dstaddr_bin, address.port})
            send_syn = {:next_event, :internal, {:send_syn, from, timeout}}
            state = %__MODULE__{pair: pair, link: pid, rcv_mss: mtu - 60}
            {:next_state, :closed, state, send_syn}

          nil ->
            {:keep_state_and_data, {:reply, from, {:error, :enetunreach}}}
        end

      {:error, _} = err ->
        {:keep_state_and_data, {:reply, from, err}}
    end
  end

  def handle_event({:call, from}, {:connect, _address, _timeout}, _, %__MODULE__{}) do
    {:keep_state_and_data, {:reply, from, {:error, :eisconn}}}
  end

  # Connect completion after :nowait - already established
  def handle_event({:call, from}, {:connect, _address, _timeout}, :established, %__MODULE__{}) do
    {:keep_state_and_data, {:reply, from, :ok}}
  end

  def handle_event(:internal, {:send_syn, from, timeout}, :closed, %__MODULE__{} = state) do
    iss = :crypto.strong_rand_bytes(4) |> :binary.decode_unsigned()
    rcv_wnd = 65535

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
        new_state = %{base_state | connect_select: {caller_pid, ref}}
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
  def handle_event(:info, segment, {:syn_sent, from}, %__MODULE__{} = state) when is_tuple(from) do
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
  def handle_event(:info, segment, {:syn_sent, :nowait}, %__MODULE__{} = state) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: seq, ack: ack, window: window, options: options} ->
        syn? = :syn in flags
        ack? = :ack in flags
        rst? = :rst in flags

        cond do
          rst? ->
            # Connection refused - no notification, caller will get error on next connect call
            reset_state(state)
            actions = [{{:timeout, :rto}, :cancel}]
            {:next_state, :closed, nil, actions}

          syn? and ack? and ack == state.iss + 1 ->
            # Valid SYN-ACK: send ACK, notify caller, transition to ESTABLISHED
            send_ack(seq + 1, state)

            snd_mss = Map.get(options, :mss, @default_mss)

            # Notify the caller that connect can complete
            case state.connect_select do
              {caller_pid, ref} -> notify_select(caller_pid, ref)
              nil -> :ok
            end

            new_state = %{
              state
              | irs: seq,
                rcv_nxt: seq + 1,
                snd_una: ack,
                snd_wnd: window,
                snd_mss: snd_mss,
                syn_retransmit_count: 0,
                rto_ms: @initial_rto_ms,
                connect_select: nil
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
      # Max retries exceeded - no notification, caller will get error on next connect call
      reset_state(state)
      {:next_state, :closed, nil}
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

  # --- Send in invalid states ---

  # Not connected
  def handle_event({:call, from}, {:send, _data, _timeout}, :closed, nil) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  # Connection closing - can't send after initiating close
  def handle_event({:call, from}, {:send, _data, _timeout}, state_name, %__MODULE__{})
      when state_name in [:fin_wait_1, :fin_wait_2, :closing, :last_ack, :time_wait] do
    {:keep_state_and_data, {:reply, from, {:error, :epipe}}}
  end

  # --- Established state: send ---

  def handle_event({:call, from}, {:send, data, timeout}, :established, %__MODULE__{} = state) do
    available = send_window_available(state)

    cond do
      available > 0 ->
        # Window available, enqueue data and return immediately
        new_state = %{state | send_buffer: DataBuffer.append(state.send_buffer, data)}
        {:keep_state, new_state, [{:reply, from, :ok}, {:next_event, :internal, :flush_send_buffer}]}

      timeout == :nowait ->
        # Window exhausted, return select tuple
        ref = make_ref()
        {caller_pid, _} = from
        waiter = {caller_pid, ref, data}
        new_state = %{state | send_waiters: state.send_waiters ++ [waiter]}
        {:keep_state, new_state, {:reply, from, {:select, {:select_info, :send, ref}}}}

      timeout == :infinity ->
        # Block until window opens
        ref = make_ref()
        waiter = {from, ref, data, nil}
        new_state = %{state | send_waiters: state.send_waiters ++ [waiter]}
        {:keep_state, new_state}

      is_integer(timeout) ->
        # Block with timeout
        ref = make_ref()
        timer_ref = make_ref()
        waiter = {from, ref, data, timer_ref}
        new_state = %{state | send_waiters: state.send_waiters ++ [waiter]}
        actions = [{{:timeout, timer_ref}, timeout, {:send_timeout, timer_ref}}]
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
        {:keep_state, new_state, {:reply, from, {:error, :timeout}}}

      nil ->
        # Already fulfilled, ignore
        :keep_state_and_data
    end
  end

  def handle_event(:internal, :flush_send_buffer, :established, %__MODULE__{} = state) do
    if DataBuffer.empty?(state.send_buffer) do
      :keep_state_and_data
    else
      do_flush_send_buffer(state)
    end
  end

  # --- Established state: recv ---

  def handle_event({:call, from}, {:recv, length, timeout}, :established, %__MODULE__{} = state) do
    case deliver_data(state.recv_buffer, length) do
      {:ok, data, rest} ->
        new_state = %{state | recv_buffer: rest}
        {:keep_state, new_state, {:reply, from, {:ok, data}}}

      :wait ->
        case timeout do
          :nowait ->
            # Return select tuple immediately, store caller info for notification
            ref = make_ref()
            {caller_pid, _} = from
            new_state = %{state | recv_select: {caller_pid, ref, length}}
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

  def handle_event(:info, segment, :established, %__MODULE__{} = state) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: seq, ack: ack, payload: payload, window: window} ->
        rst? = :rst in flags
        ack? = :ack in flags
        fin? = :fin in flags

        cond do
          rst? ->
            reset_state(state)
            # Notify any recv waiters and cancel their timers
            actions =
              Enum.flat_map(state.recv_waiters, fn {from, _length, timer_ref} ->
                [
                  {:reply, from, {:error, :econnreset}},
                  {{:timeout, timer_ref}, :cancel}
                ]
              end)

            {:next_state, :closed, nil, actions}

          fin? and seq == state.rcv_nxt ->
            # FIN from peer - handle any data with it, then transition to CLOSE_WAIT
            data_len = byte_size(payload)
            new_rcv_nxt = wrap_seq(state.rcv_nxt + data_len + 1)
            new_recv_buffer = state.recv_buffer <> payload
            new_snd_una = if ack > state.snd_una, do: ack, else: state.snd_una

            # Send ACK for FIN (and any data)
            send_ack(new_rcv_nxt, %{state | rcv_nxt: new_rcv_nxt})

            # Notify :nowait recv caller if pending
            new_recv_select =
              case state.recv_select do
                {caller_pid, ref, _length} ->
                  notify_select(caller_pid, ref)
                  nil

                nil ->
                  nil
              end

            # Notify waiters: deliver buffered data or EOF
            {new_recv_buffer, new_waiters, replies} =
              process_waiters_eof(new_recv_buffer, state.recv_waiters)

            new_state = %{
              state
              | rcv_nxt: new_rcv_nxt,
                recv_buffer: new_recv_buffer,
                recv_waiters: new_waiters,
                recv_select: new_recv_select,
                snd_una: new_snd_una,
                snd_wnd: window,
                fin_received: true
            }

            {:next_state, :close_wait, new_state, replies}

          ack? and seq == state.rcv_nxt and byte_size(payload) > 0 ->
            # Data segment with expected sequence number
            new_rcv_nxt = wrap_seq(state.rcv_nxt + byte_size(payload))
            new_recv_buffer = state.recv_buffer <> payload

            # Send ACK for received data
            send_ack(new_rcv_nxt, %{state | rcv_nxt: new_rcv_nxt})

            # Notify :nowait recv caller if pending
            new_recv_select =
              case state.recv_select do
                {caller_pid, ref, _length} ->
                  notify_select(caller_pid, ref)
                  nil

                nil ->
                  nil
              end

            # Check if any blocking waiters can be satisfied
            {new_recv_buffer, new_waiters, replies} =
              process_waiters(new_recv_buffer, state.recv_waiters)

            # Process ACK portion to update retransmission queue
            {ack_state, timer_actions} = process_ack(state, ack, window)

            new_state = %{
              ack_state
              | rcv_nxt: new_rcv_nxt,
                recv_buffer: new_recv_buffer,
                recv_waiters: new_waiters,
                recv_select: new_recv_select
            }

            {:keep_state, new_state, replies ++ timer_actions}

          ack? and byte_size(payload) == 0 ->
            # Pure ACK - process ACK and update retransmission queue
            {new_state, timer_actions} = process_ack(state, ack, window)
            {:keep_state, new_state, timer_actions}

          true ->
            # Out of order or unexpected - ignore for now
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

  # --- Active close from established ---

  def handle_event({:call, from}, :close, :established, %__MODULE__{} = state) do
    send_fin(state)
    new_state = %{state | snd_nxt: wrap_seq(state.snd_nxt + 1)}
    {:next_state, :fin_wait_1, new_state, {:reply, from, :ok}}
  end

  # --- FIN_WAIT_1 state ---

  def handle_event(:info, segment, :fin_wait_1, %__MODULE__{} = state) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: seq, ack: ack, window: window} ->
        fin? = :fin in flags
        ack? = :ack in flags
        rst? = :rst in flags
        ack_of_fin? = ack? and ack == state.snd_nxt

        cond do
          rst? ->
            reset_state(state)
            {:next_state, :closed, nil}

          fin? and ack_of_fin? ->
            # FIN+ACK of our FIN - go directly to TIME_WAIT
            send_ack(seq + 1, %{state | rcv_nxt: seq + 1})
            new_state = %{state | rcv_nxt: wrap_seq(seq + 1), snd_wnd: window, fin_received: true}

            {:next_state, :time_wait, new_state,
             {{:timeout, :time_wait}, @time_wait_ms, :time_wait_expired}}

          fin? ->
            # FIN but not ACK of our FIN - simultaneous close
            send_ack(seq + 1, %{state | rcv_nxt: seq + 1})
            new_state = %{state | rcv_nxt: wrap_seq(seq + 1), snd_wnd: window, fin_received: true}
            {:next_state, :closing, new_state}

          ack_of_fin? ->
            # ACK of our FIN - move to FIN_WAIT_2
            new_state = %{state | snd_wnd: window}
            {:next_state, :fin_wait_2, new_state}

          true ->
            :keep_state_and_data
        end

      _ ->
        :keep_state_and_data
    end
  end

  # --- FIN_WAIT_2 state ---

  def handle_event(:info, segment, :fin_wait_2, %__MODULE__{} = state) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: seq, ack: _ack, payload: payload, window: window} ->
        fin? = :fin in flags
        ack? = :ack in flags
        rst? = :rst in flags

        cond do
          rst? ->
            reset_state(state)
            {:next_state, :closed, nil}

          fin? and seq == state.rcv_nxt ->
            # FIN from peer - ACK it and go to TIME_WAIT
            # Handle any data that came with the FIN
            new_rcv_nxt = wrap_seq(state.rcv_nxt + byte_size(payload) + 1)
            send_ack(new_rcv_nxt, %{state | rcv_nxt: new_rcv_nxt})
            new_state = %{state | rcv_nxt: new_rcv_nxt, snd_wnd: window, fin_received: true}

            {:next_state, :time_wait, new_state,
             {{:timeout, :time_wait}, @time_wait_ms, :time_wait_expired}}

          ack? and seq == state.rcv_nxt and byte_size(payload) > 0 ->
            # Data segment - half-close allows peer to still send data
            new_rcv_nxt = wrap_seq(state.rcv_nxt + byte_size(payload))
            send_ack(new_rcv_nxt, %{state | rcv_nxt: new_rcv_nxt})

            new_state = %{
              state
              | rcv_nxt: new_rcv_nxt,
                recv_buffer: state.recv_buffer <> payload,
                snd_wnd: window
            }

            {:keep_state, new_state}

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

  def handle_event(:info, segment, :time_wait, %__MODULE__{} = state) do
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

  def handle_event(:info, segment, :closing, %__MODULE__{} = state) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, ack: ack, window: window} ->
        ack? = :ack in flags
        rst? = :rst in flags
        ack_of_fin? = ack? and ack == state.snd_nxt

        cond do
          rst? ->
            reset_state(state)
            {:next_state, :closed, nil}

          ack_of_fin? ->
            # ACK of our FIN - go to TIME_WAIT
            new_state = %{state | snd_wnd: window}

            {:next_state, :time_wait, new_state,
             {{:timeout, :time_wait}, @time_wait_ms, :time_wait_expired}}

          true ->
            :keep_state_and_data
        end

      _ ->
        :keep_state_and_data
    end
  end

  # --- CLOSE_WAIT state (peer closed, we can still send) ---

  def handle_event({:call, from}, {:send, data, timeout}, :close_wait, %__MODULE__{} = state) do
    available = send_window_available(state)

    cond do
      available > 0 ->
        # Window available, enqueue data and return immediately
        new_state = %{state | send_buffer: DataBuffer.append(state.send_buffer, data)}
        {:keep_state, new_state, [{:reply, from, :ok}, {:next_event, :internal, :flush_send_buffer}]}

      timeout == :nowait ->
        # Window exhausted, return select tuple
        ref = make_ref()
        {caller_pid, _} = from
        waiter = {caller_pid, ref, data}
        new_state = %{state | send_waiters: state.send_waiters ++ [waiter]}
        {:keep_state, new_state, {:reply, from, {:select, {:select_info, :send, ref}}}}

      timeout == :infinity ->
        # Block until window opens
        ref = make_ref()
        waiter = {from, ref, data, nil}
        new_state = %{state | send_waiters: state.send_waiters ++ [waiter]}
        {:keep_state, new_state}

      is_integer(timeout) ->
        # Block with timeout
        ref = make_ref()
        timer_ref = make_ref()
        waiter = {from, ref, data, timer_ref}
        new_state = %{state | send_waiters: state.send_waiters ++ [waiter]}
        actions = [{{:timeout, timer_ref}, timeout, {:send_timeout, timer_ref}}]
        {:keep_state, new_state, actions}
    end
  end

  def handle_event(:internal, :flush_send_buffer, :close_wait, %__MODULE__{} = state) do
    if DataBuffer.empty?(state.send_buffer) do
      :keep_state_and_data
    else
      do_flush_send_buffer(state)
    end
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
        {:keep_state, new_state, {:reply, from, {:error, :timeout}}}

      nil ->
        # Already fulfilled, ignore
        :keep_state_and_data
    end
  end

  def handle_event({:call, from}, {:recv, length, _timeout}, :close_wait, %__MODULE__{} = state) do
    case deliver_data(state.recv_buffer, length) do
      {:ok, data, rest} ->
        new_state = %{state | recv_buffer: rest}
        {:keep_state, new_state, {:reply, from, {:ok, data}}}

      :wait ->
        # No data and peer already sent FIN - return EOF
        {:keep_state_and_data, {:reply, from, {:ok, <<>>}}}
    end
  end

  def handle_event({:call, from}, :close, :close_wait, %__MODULE__{} = state) do
    send_fin(state)
    new_state = %{state | snd_nxt: wrap_seq(state.snd_nxt + 1)}
    {:next_state, :last_ack, new_state, {:reply, from, :ok}}
  end

  def handle_event(:info, segment, :close_wait, %__MODULE__{} = state) do
    # Handle ACKs for data we sent
    case Tcp.parse_segment(segment) do
      %{flags: flags, ack: ack, window: window} ->
        if :rst in flags do
          reset_state(state)
          {:next_state, :closed, nil}
        else
          if :ack in flags do
            # Process ACK and update retransmission queue
            {new_state, timer_actions} = process_ack(state, ack, window)
            {:keep_state, new_state, timer_actions}
          else
            :keep_state_and_data
          end
        end

      _ ->
        :keep_state_and_data
    end
  end

  # --- LAST_ACK state ---

  def handle_event(:info, segment, :last_ack, %__MODULE__{} = state) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, ack: ack} ->
        rst? = :rst in flags
        ack? = :ack in flags
        ack_of_fin? = ack? and ack == state.snd_nxt

        cond do
          rst? ->
            reset_state(state)
            {:next_state, :closed, nil}

          ack_of_fin? ->
            # ACK of our FIN - connection fully closed
            reset_state(state)
            {:next_state, :closed, nil}

          true ->
            :keep_state_and_data
        end

      _ ->
        :keep_state_and_data
    end
  end

  # --- Catch-all handlers ---

  # Send/recv on non-established socket
  def handle_event({:call, from}, {:send, _data}, _state, _state_data) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  def handle_event({:call, from}, {:recv, _length, _timeout}, _state, _state_data) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  def handle_event({:call, from}, :close, _state, _state_data) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  defp retransmit_syn(state, timeout_event) do
    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(state.pair, state.iss, 0, [:syn], state.rcv_wnd, mss: state.rcv_mss)

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

  defp do_retransmit(
         %__MODULE__{unacked_segments: [{seq, _seq_end, payload, count} | rest]} = state
       ) do
    if count >= @max_retransmit_count do
      # Max retries exceeded - connection failure
      reset_state(state)
      actions = notify_recv_waiters_error(state.recv_waiters, :etimedout)
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
          state.rcv_wnd,
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

  defp do_flush_send_buffer(%__MODULE__{} = state) do
    # Take up to snd_mss bytes from buffer
    mss = state.snd_mss || @default_mss
    {payload_iodata, new_send_buffer} = DataBuffer.take(state.send_buffer, mss)
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
        state.rcv_wnd,
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

    # Build actions: continue flushing if more data, start RTO timer if not active
    actions = []

    actions =
      if not DataBuffer.empty?(new_send_buffer),
        do: [{:next_event, :internal, :flush_send_buffer} | actions],
        else: actions

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

  defp reset_state(%__MODULE__{} = state) do
    Application.deregister_socket_pair(state.pair)
  end

  defp send_ack(ack_num, %__MODULE__{} = state) do
    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    tcp_segment = Tcp.build_segment(state.pair, state.snd_nxt, ack_num, [:ack], state.rcv_wnd)

    packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
    Tricep.Link.send(state.link, packet)
  end

  defp send_rst(seq_num, %__MODULE__{} = state) do
    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    tcp_segment = Tcp.build_segment(state.pair, seq_num, 0, [:rst], 0)

    packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
    Tricep.Link.send(state.link, packet)
  end

  defp send_fin(%__MODULE__{} = state) do
    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(state.pair, state.snd_nxt, state.rcv_nxt, [:fin, :ack], state.rcv_wnd)

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

  # Calculate available send window (for backpressure detection)
  defp send_window_available(state) do
    bytes_in_flight = wrap_seq(state.snd_nxt - state.snd_una)
    max(0, state.snd_wnd - bytes_in_flight)
  end

  # Send select notification to caller
  defp notify_select(caller_pid, ref) do
    send(caller_pid, {:"$socket", self(), :select, ref})
  end

  # Process ACK and update retransmission queue
  # Returns {new_state, timer_actions}
  defp process_ack(state, ack, window) do
    if seq_gt(ack, state.snd_una) do
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

      # Manage RTO timer based on remaining unacked segments
      timer_actions =
        if new_unacked == [] do
          # All data acknowledged - cancel timer
          [{{:timeout, :rto}, :cancel}]
        else
          # More unacked data - restart timer with fresh RTO
          [{{:timeout, :rto}, @initial_rto_ms, :retransmit}]
        end

      {%{new_state | rto_timer_active: new_unacked != []}, timer_actions ++ send_waiter_actions}
    else
      # Duplicate or old ACK - just update window (but still check send waiters)
      base_state = %{state | snd_wnd: window}
      {new_state, send_waiter_actions} = process_send_waiters(base_state)
      {new_state, send_waiter_actions}
    end
  end

  # Process send_waiters when window opens
  defp process_send_waiters(%{send_waiters: []} = state) do
    {state, []}
  end

  defp process_send_waiters(state) do
    available = send_window_available(state)

    if available > 0 do
      case state.send_waiters do
        [] ->
          {state, []}

        [{caller_pid, ref, data} | rest] when is_pid(caller_pid) ->
          # :nowait waiter - notify and enqueue data
          notify_select(caller_pid, ref)
          new_send_buffer = DataBuffer.append(state.send_buffer, data)
          new_state = %{state | send_waiters: rest, send_buffer: new_send_buffer}
          # Return flush action so data gets sent
          {new_state, [{:next_event, :internal, :flush_send_buffer}]}

        [{from, _ref, data, timer_ref} | rest] when is_tuple(from) ->
          # Blocking waiter - enqueue data and reply
          new_send_buffer = DataBuffer.append(state.send_buffer, data)
          new_state = %{state | send_waiters: rest, send_buffer: new_send_buffer}
          cancel_action = if timer_ref, do: [{{:timeout, timer_ref}, :cancel}], else: []
          {new_state, [{:reply, from, :ok}, {:next_event, :internal, :flush_send_buffer}] ++ cancel_action}
      end
    else
      {state, []}
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
