defmodule Tricep.Socket do
  @moduledoc false

  @behaviour :gen_statem

  import Bitwise

  alias Tricep.Application
  alias Tricep.DataBuffer
  alias Tricep.Tcp
  alias Tricep.Tcp.ChallengeAckLimiter
  alias Tricep.Tcp.ReceiveReassembly
  alias Tricep.Tcp.Sequence
  alias Tricep.Tcp.Synchronized
  alias Tricep.Tcp.Tcb

  require Logger
  require Tcp

  @type socket_timeout :: non_neg_integer() | :infinity | :nowait
  @type select_info :: {:select_info, :accept | :connect | :recv | :send, reference()}

  defguardp valid_socket_timeout(timeout)
            when timeout in [:infinity, :nowait] or (is_integer(timeout) and timeout >= 0)

  defguardp valid_recv_length(length) when is_integer(length) and length >= 0

  @spec connect(pid(), :socket.sockaddr_in6(), socket_timeout()) ::
          :ok | {:error, any()} | {:select, select_info()}
  def connect(pid, address, timeout \\ :infinity)

  def connect(pid, address, timeout) when is_pid(pid) and valid_socket_timeout(timeout) do
    :gen_statem.call(pid, {:connect, address, timeout})
  end

  def connect(pid, _address, _timeout) when is_pid(pid), do: {:error, :einval}

  @spec bind(pid(), :socket.sockaddr_in6()) :: :ok | {:error, atom()}
  def bind(pid, address) when is_pid(pid) do
    :gen_statem.call(pid, {:bind, address})
  end

  @spec sockname(pid()) :: {:ok, :socket.sockaddr_in6()} | {:error, atom()}
  def sockname(pid) when is_pid(pid) do
    :gen_statem.call(pid, :sockname)
  end

  @spec listen(pid(), pos_integer()) :: :ok | {:error, atom()}
  def listen(pid, backlog \\ 5) when is_pid(pid) do
    :gen_statem.call(pid, {:listen, backlog})
  end

  @spec accept(pid(), socket_timeout()) ::
          {:ok, pid()} | {:error, atom()} | {:select, select_info()}
  def accept(pid, timeout \\ :infinity)

  def accept(pid, timeout) when is_pid(pid) and valid_socket_timeout(timeout) do
    :gen_statem.call(pid, {:accept, timeout})
  end

  def accept(pid, _timeout) when is_pid(pid), do: {:error, :einval}

  @spec send_data(pid(), binary(), socket_timeout()) ::
          :ok | {:error, atom()} | {:select, select_info()}
  def send_data(pid, data, timeout \\ :infinity)

  def send_data(pid, <<>>, timeout) when is_pid(pid) and valid_socket_timeout(timeout), do: :ok

  def send_data(pid, data, timeout)
      when is_pid(pid) and is_binary(data) and valid_socket_timeout(timeout) do
    :gen_statem.call(pid, {:send, data, timeout})
  end

  def send_data(pid, data, _timeout) when is_pid(pid) and is_binary(data),
    do: {:error, :einval}

  @spec recv(pid(), non_neg_integer(), socket_timeout()) ::
          {:ok, binary()} | {:error, atom()} | {:select, select_info()}
  def recv(pid, length \\ 0, timeout \\ :infinity)

  def recv(pid, length, timeout)
      when is_pid(pid) and valid_recv_length(length) and valid_socket_timeout(timeout) do
    :gen_statem.call(pid, {:recv, length, timeout})
  end

  def recv(pid, _length, _timeout) when is_pid(pid), do: {:error, :einval}

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

      cond do
        pid = Application.lookup_socket_pair(pair) ->
          send(pid, segment)

        listener = passive_listener(dst_addr, dst_port, segment) ->
          send(listener, {:passive_syn, src_addr, dst_addr, src_port, dst_port, segment})

        true ->
          send_closed_reset(src_addr, dst_addr, src_port, dst_port, segment)
      end
    end

    :ok
  end

  # Ignore malformed packets that are too short to parse
  def handle_packet(_src_addr, _dst_addr, _segment), do: :ok

  def handle_icmpv6_error(
        src_addr,
        dst_addr,
        <<src_port::16, dst_port::16, sequence::32, rest::binary>>,
        event
      ) do
    pair = {{src_addr, src_port}, {dst_addr, dst_port}}

    if pid = Application.lookup_socket_pair(pair) do
      send(pid, {:icmpv6_error, event, quoted_tcp_details(sequence, rest)})
    else
      Logger.debug("Ignoring ICMPv6 error for an unmatched TCP socket tuple")
    end

    :ok
  end

  def handle_icmpv6_error(_src_addr, _dst_addr, _segment, _event), do: :ok

  # ICMPv6 quotes normally include the complete TCP header, but RFC 5927 only
  # needs the sequence number. Handshake errors additionally require the SYN
  # bit, so a truncated quote can never abort a pending connection.
  defp quoted_tcp_details(
         sequence,
         <<_acknowledgment::32, _data_offset::4, _reserved::4, flags::8, _::binary>>
       ) do
    %{seq: sequence, syn?: (flags &&& 0x02) != 0}
  end

  defp quoted_tcp_details(sequence, _rest), do: %{seq: sequence, syn?: false}

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
    if valid_socket_options?(socket_opts(opts)) do
      :gen_statem.start_link(__MODULE__, opts, hibernate_after: 15_000)
    else
      {:error, :einval}
    end
  end

  @spec start_passive_connection(map()) :: :ignore | {:error, any()} | {:ok, pid()}
  def start_passive_connection(opts) do
    :gen_statem.start(__MODULE__, {:passive_connection, opts}, hibernate_after: 15_000)
  end

  use TypedStruct

  @ipv6_min_mtu 1280
  @tcp_ipv6_header_size 60
  # Default MSS for IPv6 (1280 min MTU - 40 IPv6 header - 20 TCP header)
  @default_mss @ipv6_min_mtu - @tcp_ipv6_header_size
  # Harden against peer-controlled packet and CPU amplification from tiny MSS
  # values. This matches Linux's default tcp_min_snd_mss compatibility floor.
  @minimum_snd_mss 48
  # IPv6 payload length is 16-bit and jumbograms are not supported. Reserve
  # the fixed 20-byte TCP header so Ip.wrap/4 can always encode data segments.
  @maximum_ipv6_tcp_mss 65_535 - 20
  @default_recv_buffer_size 65_535
  @max_window Tcp.max_window()
  @max_window_scale 14
  @max_scaled_tcp_window @max_window <<< @max_window_scale
  @default_fin_wait_2_timeout_ms 60_000
  @ephemeral_port_first 49_152
  @ephemeral_port_last 65_535
  @ephemeral_port_count @ephemeral_port_last - @ephemeral_port_first + 1

  # Retransmission timeout constants
  @initial_rto_ms 1_000
  @max_rto_ms 60_000
  @max_retransmit_count 5
  @initial_persist_timeout_ms 1_000
  @max_persist_timeout_ms 60_000
  @any_addr <<0::128>>

  @typep addr_port() :: {binary(), non_neg_integer()}
  typedstruct enforce: true do
    field :pair, {addr_port(), addr_port()}
    field :link, pid()
    # Immutable socket options survive a TCP incarnation so a closed socket
    # can reconnect with the same configuration and a fresh TCB.
    field :socket_opts, map() | keyword(), default: %{}
    # Protocol control state is owned by the pure TCP control block. The
    # adapter fields below contain only OTP, I/O, buffering, and timer state.
    field :tcb, Tcb.t(), default: %Tcb{}
    # Buffers for data transfer
    field :send_buffer, DataBuffer.t(), default: DataBuffer.new()
    field :recv_buffer, binary(), default: <<>>
    field :out_of_order_segments, list(), default: []
    # Count chunks evicted by the hard receive-reassembly cap during this TCP
    # incarnation. It is intentionally connection-local: a fresh connection
    # starts at zero, even when a closed socket reconnects.
    field :reassembly_eviction_count, non_neg_integer(), default: 0
    # The FIN sequence-space marker may arrive before the queued data that
    # precedes it. Its payload start proves that the marker was carried by
    # queued data rather than an unrelated bare out-of-order FIN.
    field :out_of_order_fin, Sequence.sequence_number() | nil, default: nil
    field :out_of_order_fin_payload_start, Sequence.sequence_number() | nil, default: nil
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
    # Applicable ICMPv6 hard errors can be advisory. Keep the latest reason
    # so retry exhaustion can report useful context.
    field :soft_error, atom() | nil, default: nil
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
    # Per-connection RFC 5961 challenge-ACK accounting. The socket owns the
    # limiter because it owns the connection's receive path and TCB.
    field :challenge_ack_limiter, ChallengeAckLimiter.t(), default: ChallengeAckLimiter.new()
    # Listening socket that owns this connection while the passive handshake completes
    field :passive_listener, pid() | nil, default: nil
  end

  # TIME_WAIT duration (2*MSL - using short value for TUN-based stack)
  @time_wait_ms 2_000

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init({:passive_connection, opts}) do
    if valid_socket_options?(Map.get(opts, :socket_opts, %{})) do
      state = passive_connection_state(opts)

      case Application.register_socket_pair(state.pair) do
        :ok ->
          {:ok, :syn_received, state}

        {:error, reason} ->
          {:stop, reason}
      end
    else
      {:stop, :einval}
    end
  end

  def init(opts) do
    socket_opts = socket_opts(opts)

    if valid_socket_options?(socket_opts) do
      {:ok, :closed, %{socket_opts: socket_opts}}
    else
      {:stop, :einval}
    end
  end

  @impl true
  def handle_event({:call, from}, {:bind, address}, :closed, closed_data) do
    case validate_sockaddr_in6(address, 0..65_535) do
      {:ok, local_addr, local_port} ->
        case bind_local_socket(local_addr, local_port) do
          {:ok, local_port} ->
            data =
              closed_data
              |> Map.put(:local_addr, local_addr)
              |> Map.put(:local_port, local_port)

            {:next_state, :bound, data, {:reply, from, :ok}}

          {:error, :eaddrinuse} ->
            {:keep_state_and_data, {:reply, from, {:error, :eaddrinuse}}}

          {:error, :eaddrnotavail} ->
            {:keep_state_and_data, {:reply, from, {:error, :eaddrnotavail}}}
        end

      {:error, reason} ->
        {:keep_state_and_data, {:reply, from, {:error, reason}}}
    end
  end

  def handle_event({:call, from}, {:listen, backlog}, :bound, bound_data)
      when is_integer(backlog) and backlog > 0 do
    local_addr = Map.fetch!(bound_data, :local_addr)
    local_port = Map.fetch!(bound_data, :local_port)

    case Application.register_listener(local_addr, local_port) do
      :ok ->
        listen_data =
          bound_data
          |> Map.put(:backlog, backlog)
          |> Map.put(:pending_count, 0)
          |> Map.put(:accept_queue, [])
          |> Map.put(:accept_waiters, [])
          |> Map.put(:accept_selects, [])
          |> Map.put(:children, %{})

        {:next_state, :listen, listen_data, {:reply, from, :ok}}

      {:error, {:already_registered, _pid}} ->
        {:keep_state_and_data, {:reply, from, {:error, :eaddrinuse}}}
    end
  end

  def handle_event({:call, from}, {:listen, backlog}, :listen, listen_data)
      when is_integer(backlog) and backlog > 0 do
    {:keep_state, %{listen_data | backlog: backlog}, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, {:accept, timeout}, :listen, listen_data) do
    case listen_data.accept_queue do
      [child | rest] ->
        {listen_data, actions} =
          listen_data
          |> Map.put(:accept_queue, rest)
          |> accept_child(child, [{:reply, from, {:ok, child}}])

        {:keep_state, listen_data, actions}

      [] ->
        {:keep_state_and_data, [{:next_event, :internal, {:wait_accept, from, timeout}}]}
    end
  end

  def handle_event(:internal, {:wait_accept, from, :nowait}, :listen, listen_data) do
    ref = make_ref()
    {caller_pid, _} = from

    new_data = %{
      listen_data
      | accept_selects: listen_data.accept_selects ++ [{caller_pid, ref}]
    }

    {:keep_state, new_data, {:reply, from, {:select, {:select_info, :accept, ref}}}}
  end

  def handle_event(:internal, {:wait_accept, from, :infinity}, :listen, listen_data) do
    waiter = {from, make_ref(), nil}
    new_data = %{listen_data | accept_waiters: listen_data.accept_waiters ++ [waiter]}
    {:keep_state, new_data}
  end

  def handle_event(:internal, {:wait_accept, from, timeout}, :listen, listen_data)
      when is_integer(timeout) and timeout >= 0 do
    timer_ref = make_ref()
    waiter = {from, timer_ref, timer_ref}
    new_data = %{listen_data | accept_waiters: listen_data.accept_waiters ++ [waiter]}
    {:keep_state, new_data, {{:timeout, timer_ref}, timeout, {:accept_timeout, timer_ref}}}
  end

  def handle_event(:internal, {:wait_accept, from, _timeout}, :listen, _listen_data) do
    {:keep_state_and_data, {:reply, from, {:error, :einval}}}
  end

  def handle_event(
        {:timeout, timer_ref},
        {:accept_timeout, timer_ref},
        :listen,
        listen_data
      ) do
    case List.keytake(listen_data.accept_waiters, timer_ref, 1) do
      {{from, ^timer_ref, ^timer_ref}, rest} ->
        {:keep_state, %{listen_data | accept_waiters: rest}, {:reply, from, {:error, :timeout}}}

      nil ->
        :keep_state_and_data
    end
  end

  def handle_event(
        :info,
        {:passive_syn, src_addr, dst_addr, src_port, dst_port, segment},
        :listen,
        listen_data
      ) do
    case passive_connection_opts(
           listen_data,
           src_addr,
           dst_addr,
           src_port,
           dst_port,
           segment
         ) do
      {:ok, opts} -> start_passive_child(listen_data, opts)
      :ignore -> :keep_state_and_data
    end
  end

  def handle_event(:info, {:passive_established, child}, :listen, listen_data) do
    case Map.get(listen_data.children, child) do
      {ref, :pending} ->
        listen_data =
          listen_data
          |> Map.put(:pending_count, max(0, listen_data.pending_count - 1))
          |> put_child(child, ref, :queued)

        {listen_data, actions} = enqueue_accepted_child(listen_data, child)
        {:keep_state, listen_data, actions}

      _ ->
        :keep_state_and_data
    end
  end

  def handle_event(:info, {:passive_failed, child}, :listen, listen_data) do
    {:keep_state, remove_listen_child(listen_data, child)}
  end

  def handle_event(:info, {:passive_failed, child, reason}, :listen, listen_data) do
    Logger.debug(
      "Passive TCP handshake failed after SYN-ACK retry exhaustion: #{inspect(reason)}"
    )

    {:keep_state, remove_listen_child(listen_data, child)}
  end

  def handle_event(:info, {:DOWN, ref, :process, child, _reason}, :listen, listen_data) do
    case Map.get(listen_data.children, child) do
      {^ref, _status} ->
        {:keep_state, remove_listen_child(listen_data, child)}

      _ ->
        :keep_state_and_data
    end
  end

  @impl true
  def handle_event({:call, from}, {:connect, address, timeout}, :closed, closed_data) do
    case validate_sockaddr_in6(address) do
      {:ok, dstaddr_bin, dst_port} ->
        connect_from_closed(from, timeout, closed_data, dstaddr_bin, dst_port)

      {:error, reason} ->
        {:keep_state_and_data, {:reply, from, {:error, reason}}}
    end
  end

  def handle_event({:call, from}, {:connect, address, timeout}, :bound, bound_data) do
    case validate_sockaddr_in6(address) do
      {:ok, dstaddr_bin, dst_port} ->
        connect_from_bound(from, timeout, bound_data, dstaddr_bin, dst_port)

      {:error, reason} ->
        {:keep_state_and_data, {:reply, from, {:error, reason}}}
    end
  end

  def handle_event({:call, from}, :sockname, _state_name, %{
        local_addr: local_addr,
        local_port: local_port
      }) do
    {:keep_state_and_data, {:reply, from, {:ok, sockaddr_in6(local_addr, local_port)}}}
  end

  def handle_event(
        {:call, from},
        :sockname,
        _state_name,
        %__MODULE__{pair: {{local_addr, local_port}, _remote}}
      ) do
    {:keep_state_and_data, {:reply, from, {:ok, sockaddr_in6(local_addr, local_port)}}}
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
        closed_data
      ) do
    case take_select_for_pid(connect_selects, caller_pid) do
      {{^caller_pid, _ref}, []} ->
        {:next_state, :closed, closed_data, {:reply, from, {:error, reason}}}

      {{^caller_pid, _ref}, remaining_selects} ->
        {:next_state, {:connect_failed, remaining_selects, reason}, closed_data,
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
    syn_window = advertised_syn_window(state)

    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(state.pair, iss, 0, [:syn], syn_window,
        mss: state.tcb.rcv_mss,
        window_scale: state.tcb.rcv_wnd_scale
      )

    packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
    :ok = Tricep.Link.send(state.link, packet)

    base_state = %{
      state
      | tcb: Tcb.begin_active_open(state.tcb, iss, syn_window),
        syn_retransmit_count: 0,
        rto_ms: @initial_rto_ms,
        soft_error: nil
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
    case syn_sent_segment(state, segment) do
      :reset ->
        reset_state(state)

        {:next_state, :closed, closed_data(state),
         [
           {{:timeout, :rto}, :cancel},
           {{:timeout, :connect_timeout}, :cancel},
           {:reply, from, {:error, :econnrefused}}
         ]}

      {:established, new_state} ->
        send_ack(new_state.tcb.rcv_nxt, new_state)

        {:next_state, :established, new_state,
         [
           {{:timeout, :rto}, :cancel},
           {{:timeout, :connect_timeout}, :cancel},
           {:reply, from, :ok}
         ]}

      {:bad_ack, acknowledgment} ->
        send_rst(acknowledgment, state)
        :keep_state_and_data

      :ignore ->
        :keep_state_and_data
    end
  end

  # SYN-ACK handler for :nowait connect
  def handle_event(:info, segment, {:syn_sent, :nowait}, %__MODULE__{} = state)
      when is_binary(segment) do
    case syn_sent_segment(state, segment) do
      :reset ->
        {state_name, state_data} = nowait_connect_failure(state, :econnrefused)
        {:next_state, state_name, state_data, {{:timeout, :rto}, :cancel}}

      {:established, new_state} ->
        notify_selects(state.connect_selects)
        send_ack(new_state.tcb.rcv_nxt, new_state)
        {:next_state, :established, new_state, {{:timeout, :rto}, :cancel}}

      {:bad_ack, acknowledgment} ->
        send_rst(acknowledgment, state)
        :keep_state_and_data

      :ignore ->
        :keep_state_and_data
    end
  end

  # --- Passive open: SYN_RECEIVED child socket ---

  def handle_event(:info, :send_syn_ack, :syn_received, %__MODULE__{} = state) do
    send_syn_ack(state)
    {:keep_state, state, {{:timeout, :rto}, @initial_rto_ms, :syn_ack_timeout}}
  end

  def handle_event(:info, segment, :syn_received, %__MODULE__{} = state)
      when is_binary(segment) do
    case syn_received_segment(state, segment) do
      :acceptable_reset ->
        reset_state(state)
        notify_passive_listener(state, :passive_failed)
        {:stop, :normal}

      :challenge_ack ->
        send_challenge_ack(state)

      :silent_drop ->
        :keep_state_and_data

      :unacceptable_segment ->
        reject_unacceptable_segment(state)

      {:established, next_state, new_state, receive_actions} ->
        notify_passive_listener(state, :passive_established)
        {:next_state, next_state, new_state, receive_actions ++ [{{:timeout, :rto}, :cancel}]}

      {:bad_ack, acknowledgment} ->
        send_rst(acknowledgment, state)
        :keep_state_and_data

      :retransmit_syn_ack ->
        send_syn_ack(state)
        :keep_state_and_data

      :ignore ->
        :keep_state_and_data
    end
  end

  def handle_event({:timeout, :rto}, :syn_ack_timeout, :syn_received, %__MODULE__{} = state) do
    if state.syn_retransmit_count >= @max_retransmit_count do
      reason = retry_exhaustion_error(state)
      reset_state(state)
      notify_passive_listener(state, {:passive_failed, reason})
      {:stop, :normal}
    else
      retransmit_syn_ack(state)
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

      actions = [
        {{:timeout, :connect_timeout}, :cancel},
        {:reply, from, {:error, retry_exhaustion_error(state)}}
      ]

      {:next_state, :closed, closed_data(state), actions}
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
      {state_name, state_data} = nowait_connect_failure(state, retry_exhaustion_error(state))
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
    {:next_state, :closed, closed_data(state), actions}
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
    available = Tcb.send_window_available(state.tcb)

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
    handle_recv_call(state, from, length, timeout)
  end

  # Handle recv timeout
  def handle_event(
        {:timeout, timer_ref},
        {:recv_timeout, timer_ref},
        :established,
        %__MODULE__{} = state
      ) do
    handle_recv_timeout(state, timer_ref)
  end

  # --- Established state: incoming data ---

  def handle_event(:info, segment, :established, %__MODULE__{} = state) when is_binary(segment) do
    case Synchronized.process(state.tcb, segment, validate_ack?: true) do
      {:ok, parsed} -> handle_established_segment(state, parsed)
      outcome -> synchronized_rejection(state, outcome)
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

  def handle_event({:timeout, :persist}, :persist_probe, :fin_wait_1, %__MODULE__{} = state) do
    # A FIN consumes the next sequence number, so a persist probe here would
    # put payload at that FIN sequence. FIN_WAIT_1 cannot retain send data.
    new_state = %{
      state
      | persist_timer_active: false,
        persist_timeout_ms: @initial_persist_timeout_ms
    }

    {:keep_state, new_state, cancel_persist_timer_action(state)}
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
        {:icmpv6_error, event, quoted_tcp},
        state_name,
        %__MODULE__{} = state
      ) do
    if applicable_icmpv6_quote?(quoted_tcp, state_name, state) do
      apply_icmpv6_error(event, state_name, state)
    else
      Logger.debug(
        "Ignoring inapplicable ICMPv6 #{inspect(event)} quote in #{inspect(state_name)} state"
      )

      :keep_state_and_data
    end
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
    state
    |> Map.put(:read_shutdown, true)
    |> close_or_drain_send_buffer(from, :fin_wait_1)
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

  def handle_event({:call, from}, {:recv, length, timeout}, :fin_wait_1, %__MODULE__{} = state) do
    handle_recv_call(state, from, length, timeout)
  end

  def handle_event(
        {:timeout, timer_ref},
        {:recv_timeout, timer_ref},
        :fin_wait_1,
        %__MODULE__{} = state
      ) do
    handle_recv_timeout(state, timer_ref)
  end

  def handle_event(:info, segment, :fin_wait_1, %__MODULE__{} = state) when is_binary(segment) do
    case Synchronized.process(state.tcb, segment) do
      {:ok, parsed} ->
        handle_fin_wait_1_segment(state, parsed)

      outcome ->
        synchronized_rejection(state, outcome)
    end
  end

  # --- FIN_WAIT_2 state ---

  def handle_event({:call, from}, {:recv, length, timeout}, :fin_wait_2, %__MODULE__{} = state) do
    handle_recv_call(state, from, length, timeout)
  end

  def handle_event(
        {:timeout, timer_ref},
        {:recv_timeout, timer_ref},
        :fin_wait_2,
        %__MODULE__{} = state
      ) do
    handle_recv_timeout(state, timer_ref)
  end

  def handle_event(
        {:timeout, :fin_wait_2},
        :fin_wait_2_expired,
        :fin_wait_2,
        %__MODULE__{} = state
      ) do
    reset_connection(state, :etimedout, [{{:timeout, :fin_wait_2}, :cancel}])
  end

  def handle_event(:info, segment, :fin_wait_2, %__MODULE__{} = state) when is_binary(segment) do
    case Synchronized.process(state.tcb, segment, validate_ack?: true) do
      {:ok, parsed} ->
        handle_fin_wait_2_segment(state, parsed)

      outcome ->
        synchronized_rejection(
          state,
          outcome,
          {:connection, [{{:timeout, :fin_wait_2}, :cancel}]}
        )
    end
  end

  def handle_event(
        {:call, from},
        {:recv, length, timeout},
        state_name,
        %__MODULE__{read_shutdown: false, fin_received: true} = state
      )
      when state_name in [:closing, :last_ack, :time_wait] do
    handle_recv_call(state, from, length, timeout)
  end

  # --- TIME_WAIT state ---

  def handle_event({:timeout, :time_wait}, :time_wait_expired, :time_wait, %__MODULE__{} = state) do
    # Entering TIME_WAIT has already consumed or cancelled any RTO. This is
    # the TIME_WAIT timer's own expiry event, so no additional cancellation is
    # required before releasing the tuple.
    reset_state(state)
    {:next_state, :closed, closed_data(state)}
  end

  def handle_event(:info, segment, :time_wait, %__MODULE__{} = state) when is_binary(segment) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: sequence, payload: payload} ->
        handle_time_wait_segment(state, flags, sequence, byte_size(payload))

      _ ->
        :keep_state_and_data
    end
  end

  # --- CLOSING state (simultaneous close) ---

  def handle_event(:info, segment, :closing, %__MODULE__{} = state) when is_binary(segment) do
    case Synchronized.process(state.tcb, segment) do
      {:ok, parsed} -> handle_closing_segment(state, parsed)
      outcome -> synchronized_rejection(state, outcome, :close)
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
    available = Tcb.send_window_available(state.tcb)

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
    handle_final_recv_call(state, from, length)
  end

  def handle_event({:call, from}, :close, :close_wait, %__MODULE__{write_shutdown: true} = state) do
    {:keep_state, state, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, :close, :close_wait, %__MODULE__{} = state) do
    state
    |> Map.put(:read_shutdown, true)
    |> close_or_drain_send_buffer(from, :last_ack)
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
    case Synchronized.process(state.tcb, segment) do
      {:ok, parsed} -> handle_close_wait_segment(state, parsed)
      outcome -> synchronized_rejection(state, outcome)
    end
  end

  # --- LAST_ACK state ---

  def handle_event(:info, segment, :last_ack, %__MODULE__{} = state) when is_binary(segment) do
    case Synchronized.process(state.tcb, segment) do
      {:ok, parsed} -> handle_last_ack_segment(state, parsed)
      outcome -> synchronized_rejection(state, outcome, :close)
    end
  end

  # --- Bound/listening socket cleanup ---

  def handle_event({:call, from}, :close, :bound, bound_data) do
    deregister_bound_data(bound_data)
    closed_data = %{socket_opts: bound_data.socket_opts}
    {:next_state, :closed, closed_data, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, :close, :listen, listen_data) do
    deregister_listen_data(listen_data)
    closed_data = %{socket_opts: listen_data.socket_opts}
    actions = close_accept_actions(listen_data) ++ [{:reply, from, :ok}]
    {:next_state, :closed, closed_data, actions}
  end

  # --- Catch-all handlers ---

  def handle_event(:info, _message, _state, _state_data) do
    :keep_state_and_data
  end

  def handle_event({:call, from}, {:bind, _address}, _state, _state_data) do
    {:keep_state_and_data, {:reply, from, {:error, :einval}}}
  end

  def handle_event({:call, from}, {:listen, _backlog}, _state, _state_data) do
    {:keep_state_and_data, {:reply, from, {:error, :einval}}}
  end

  def handle_event({:call, from}, {:accept, _timeout}, _state, _state_data) do
    {:keep_state_and_data, {:reply, from, {:error, :einval}}}
  end

  def handle_event({:call, from}, :sockname, _state, _state_data) do
    {:keep_state_and_data, {:reply, from, {:error, :einval}}}
  end

  def handle_event({:call, from}, {:connect, _address, _timeout}, _state, _state_data) do
    {:keep_state_and_data, {:reply, from, {:error, :einval}}}
  end

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

  # State-specific effects begin only after Synchronized has applied the
  # common RST, sequence-window, and ACK-bound admission pipeline.
  defp handle_established_segment(state, %{
         flags: flags,
         seq: seq,
         ack: ack,
         payload: payload,
         window: window
       }) do
    fin? = :fin in flags
    ack? = :ack in flags
    payload? = payload != <<>>

    cond do
      ackless_payload_rejected_by_base?(state, ack?, fin?, seq, payload?) ->
        acknowledge_ackless_segment(state, window)

      ackless_out_of_order_bare_fin?(state, ack?, fin?, seq, payload?) ->
        acknowledge_ackless_segment(state, window)

      true ->
        flags = drop_ackless_out_of_order_fin(state, flags, ack?, fin?, seq, payload?)
        fin? = :fin in flags

        handle_established_received_segment(state, %{
          flags: flags,
          seq: seq,
          ack: ack,
          window: window,
          payload: payload,
          fin?: fin?,
          ack?: ack?,
          payload?: payload?
        })
    end
  end

  defp handle_established_received_segment(state, %{
         flags: flags,
         seq: seq,
         ack: ack,
         window: window,
         payload: payload,
         fin?: fin?,
         ack?: ack?,
         payload?: payload?
       }) do
    cond do
      payload? or fin? ->
        {receive_state, _delivered_length, fin_ready?, recv_actions} =
          deliver_received_segment(state, seq, payload, flags)

        if fin_ready? do
          handle_established_fin_ready(receive_state, ack?, ack, window, recv_actions)
        else
          {new_state, timer_actions} = process_ack_if_present(receive_state, ack?, ack, window)
          send_ack(new_state.tcb.rcv_nxt, new_state)
          {:keep_state, new_state, recv_actions ++ timer_actions}
        end

      ack? ->
        {new_state, timer_actions} = process_ack(state, ack, window)
        {:keep_state, new_state, timer_actions}

      true ->
        :keep_state_and_data
    end
  end

  # Direct and reassembly-drained FINs share send bookkeeping. Issue #120 owns
  # ACK-less admission and waiter-wake semantics, including its known wedge.
  defp handle_established_fin_ready(receive_state, ack?, ack, window, recv_actions) do
    {ack_state, ack_actions} = process_ack_if_present(receive_state, ack?, ack, window)
    transition_established_after_fin(ack_state, recv_actions ++ ack_actions)
  end

  defp transition_established_after_fin(receive_state, actions) do
    receive_state = notify_recv_select(receive_state, :eof)

    {recv_buffer, recv_waiters, replies} =
      process_waiters_eof(receive_state.recv_buffer, receive_state.recv_waiters)

    new_state =
      receive_state
      |> Map.put(:recv_buffer, recv_buffer)
      |> Map.put(:recv_waiters, recv_waiters)
      |> Map.put(:fin_received, true)
      |> refresh_receive_window()

    send_ack(new_state.tcb.rcv_nxt, new_state)
    {:next_state, :close_wait, new_state, actions ++ replies}
  end

  defp handle_fin_wait_1_segment(state, %{
         flags: flags,
         seq: seq,
         ack: ack,
         payload: payload,
         window: window
       }) do
    ack? = :ack in flags

    if ack? do
      {ack_state, ack_actions} = process_ack(state, ack, window)

      {receive_state, _delivered_length, fin_ready?, recv_actions} =
        deliver_received_segment(ack_state, seq, payload, flags)

      if (payload != <<>> or :fin in flags) and not fin_ready? do
        send_ack(receive_state.tcb.rcv_nxt, receive_state)
      end

      transition =
        fin_wait_1_transition(%{
          ack?: true,
          ack_of_fin?: ack == state.tcb.snd_nxt,
          fin?: :fin in flags,
          fin_ready?: fin_ready?,
          recv_actions: recv_actions
        })

      handle_fin_wait_1_transition(receive_state, transition, ack_actions, recv_actions)
    else
      handle_fin_wait_1_ackless_segment(state, flags, seq, payload, window)
    end
  end

  # Bug #120 owns the broader ACK-less FIN_WAIT_1 receive behavior. Retain
  # its historical commit/discard boundary while allowing an in-order FIN to
  # progress the close state as before.
  defp handle_fin_wait_1_ackless_segment(state, flags, seq, payload, window) do
    # Preserve FIN_WAIT_1's historical discard behavior for an ACK-less
    # in-order payload, but decide before reassembly can advance RCV.NXT,
    # drain queued authenticated data, or notify readers.
    if payload != <<>> and :fin not in flags and seq == state.tcb.rcv_nxt do
      send_ack(state.tcb.rcv_nxt, state)
      :keep_state_and_data
    else
      {ack_state, ack_actions} = process_ack_if_present(state, false, 0, window)
      handle_fin_wait_1_ackless_segment_after_gate(ack_state, ack_actions, flags, seq, payload)
    end
  end

  defp handle_fin_wait_1_ackless_segment_after_gate(ack_state, ack_actions, flags, seq, payload) do
    {receive_state, delivered_length, fin_ready?, recv_actions} =
      if seq == ack_state.tcb.rcv_nxt do
        deliver_received_segment(ack_state, seq, payload, flags)
      else
        {ack_state, 0, false, []}
      end

    if delivered_length > 0 and not fin_ready? do
      send_ack(receive_state.tcb.rcv_nxt, receive_state)
    end

    transition =
      fin_wait_1_transition(%{
        ack?: false,
        ack_of_fin?: false,
        fin?: :fin in flags,
        fin_ready?: fin_ready?,
        recv_actions: recv_actions
      })

    handle_fin_wait_1_transition(receive_state, transition, ack_actions, recv_actions)
  end

  defp fin_wait_1_transition(%{} = segment) do
    cond do
      segment.fin_ready? and segment.ack_of_fin? -> :time_wait
      segment.fin_ready? -> :closing
      segment.ack_of_fin? -> :fin_wait_2
      segment.ack? -> :ack
      segment.fin? -> :unready_fin
      segment.recv_actions == [] -> :no_op
      true -> :receive
    end
  end

  defp handle_fin_wait_1_transition(state, :time_wait, ack_actions, recv_actions) do
    transition_after_received_fin(state, :time_wait, ack_actions ++ recv_actions, [
      {{:timeout, :time_wait}, @time_wait_ms, :time_wait_expired}
    ])
  end

  defp handle_fin_wait_1_transition(state, :closing, ack_actions, recv_actions) do
    transition_after_received_fin(state, :closing, ack_actions ++ recv_actions)
  end

  defp handle_fin_wait_1_transition(state, :fin_wait_2, ack_actions, recv_actions) do
    {:next_state, :fin_wait_2, state,
     ack_actions ++
       recv_actions ++
       [{{:timeout, :fin_wait_2}, state.fin_wait_2_timeout_ms, :fin_wait_2_expired}]}
  end

  defp handle_fin_wait_1_transition(state, :ack, ack_actions, recv_actions) do
    {:keep_state, state, ack_actions ++ recv_actions}
  end

  defp handle_fin_wait_1_transition(state, :unready_fin, ack_actions, recv_actions) do
    send_ack(state.tcb.rcv_nxt, state)
    {:keep_state, state, ack_actions ++ recv_actions}
  end

  # Preserve the ACK-less payload acknowledgement/discard behavior; bug #120 owns its fix.
  defp handle_fin_wait_1_transition(_state, :no_op, _ack_actions, _recv_actions) do
    :keep_state_and_data
  end

  defp handle_fin_wait_1_transition(state, :receive, ack_actions, recv_actions) do
    {:keep_state, state, ack_actions ++ recv_actions}
  end

  defp handle_fin_wait_2_segment(state, %{
         flags: flags,
         seq: seq,
         ack: ack,
         payload: payload,
         window: window
       }) do
    ack? = :ack in flags
    fin? = :fin in flags

    cond do
      ackless_payload_rejected_by_base?(state, ack?, fin?, seq, payload != <<>>) ->
        acknowledge_ackless_segment(state, window)

      ackless_out_of_order_bare_fin?(state, ack?, fin?, seq, payload != <<>>) ->
        acknowledge_ackless_segment(state, window)

      true ->
        flags = drop_ackless_out_of_order_fin(state, flags, ack?, fin?, seq, payload != <<>>)
        fin? = :fin in flags
        {ack_state, ack_actions} = process_ack_if_present(state, ack?, ack, window)

        handle_fin_wait_2_received_segment(ack_state, ack_actions, flags, seq, payload, fin?)
    end
  end

  # Keep the RFC 9293 ACK-bit gate at the state boundary. Synchronized cannot
  # own it because FIN_WAIT_1 deliberately preserves its historical ACK-less
  # receive behavior for issue #120; its no-ACK SND.WND accounting stays out
  # of scope here. Before the reassembly extraction,
  # ESTABLISHED and FIN_WAIT_2 rejected an ACK-less payload that begins at or
  # overlaps RCV.NXT, while accepting an exact-sequence FIN.
  defp ackless_payload_rejected_by_base?(state, false, fin?, sequence, true) do
    (not fin? and sequence == state.tcb.rcv_nxt) or
      Sequence.gt?(state.tcb.rcv_nxt, sequence)
  end

  defp ackless_payload_rejected_by_base?(_state, _ack?, _fin?, _sequence, _payload?), do: false

  defp ackless_out_of_order_bare_fin?(state, false, true, sequence, false),
    do: Sequence.gt?(sequence, state.tcb.rcv_nxt)

  defp ackless_out_of_order_bare_fin?(_state, _ack?, _fin?, _sequence, _payload?), do: false

  defp drop_ackless_out_of_order_fin(state, flags, false, true, sequence, true) do
    if Sequence.gt?(sequence, state.tcb.rcv_nxt), do: List.delete(flags, :fin), else: flags
  end

  defp drop_ackless_out_of_order_fin(_state, flags, _ack?, _fin?, _sequence, _payload?), do: flags

  defp acknowledge_ackless_segment(state, window) do
    {new_state, timer_actions} = process_ack_if_present(state, false, 0, window)
    send_ack(new_state.tcb.rcv_nxt, new_state)
    {:keep_state, new_state, timer_actions}
  end

  defp handle_fin_wait_2_received_segment(ack_state, ack_actions, flags, seq, payload, fin?) do
    if payload != <<>> or fin? do
      {receive_state, _delivered_length, fin_ready?, recv_actions} =
        deliver_received_segment(ack_state, seq, payload, flags)

      if fin_ready? do
        transition_after_received_fin(
          receive_state,
          :time_wait,
          ack_actions ++ recv_actions,
          [
            {{:timeout, :fin_wait_2}, :cancel},
            {{:timeout, :time_wait}, @time_wait_ms, :time_wait_expired}
          ]
        )
      else
        send_ack(receive_state.tcb.rcv_nxt, receive_state)
        {:keep_state, receive_state, ack_actions ++ recv_actions}
      end
    else
      {:keep_state, ack_state, ack_actions}
    end
  end

  defp handle_closing_segment(state, %{flags: flags, ack: ack, window: window}) do
    ack? = :ack in flags
    {ack_state, ack_actions} = process_ack_if_present(state, ack?, ack, window)

    cond do
      ack? and ack == state.tcb.snd_nxt ->
        {:next_state, :time_wait, ack_state,
         ack_actions ++ [{{:timeout, :time_wait}, @time_wait_ms, :time_wait_expired}]}

      ack? ->
        {:keep_state, ack_state, ack_actions}

      true ->
        :keep_state_and_data
    end
  end

  defp handle_close_wait_segment(state, %{flags: flags, ack: ack, window: window}) do
    if :ack in flags do
      {new_state, timer_actions} = process_ack(state, ack, window)
      {:keep_state, new_state, timer_actions}
    else
      :keep_state_and_data
    end
  end

  defp handle_last_ack_segment(state, %{flags: flags, ack: ack, window: window}) do
    ack? = :ack in flags
    {ack_state, ack_actions} = process_ack_if_present(state, ack?, ack, window)

    cond do
      ack? and ack == state.tcb.snd_nxt ->
        # process_ack_if_present/4 supplies the RTO cancellation with this
        # advancing ACK before LAST_ACK releases the tuple.
        reset_state(ack_state)
        {:next_state, :closed, closed_data(ack_state), ack_actions}

      ack? ->
        {:keep_state, ack_state, ack_actions}

      true ->
        :keep_state_and_data
    end
  end

  defp passive_listener(dst_addr, dst_port, segment) do
    with %{flags: flags} <- Tcp.parse_segment(segment),
         true <- :syn in flags,
         false <- :ack in flags,
         false <- :rst in flags do
      Application.lookup_listener(dst_addr, dst_port)
    else
      _ -> nil
    end
  end

  defp send_closed_reset(src_addr, dst_addr, src_port, dst_port, segment) do
    with %{flags: flags} = parsed <- Tcp.parse_segment(segment),
         false <- :rst in flags,
         {link, {^dst_addr, _mtu}} <- Application.lookup_link(src_addr) do
      pair = {{dst_addr, dst_port}, {src_addr, src_port}}
      {seq, ack, rst_flags} = reset_fields(parsed)

      tcp_segment = Tcp.build_segment(pair, seq, ack, rst_flags, 0)
      packet = Tricep.Ip.wrap(dst_addr, src_addr, :tcp, tcp_segment)

      Tricep.Link.send(link, packet)
    else
      _ -> :ok
    end
  end

  defp reset_fields(%{flags: flags, ack: ack, seq: seq} = parsed) do
    if :ack in flags do
      {ack, 0, [:rst]}
    else
      {0, Sequence.wrap(seq + Sequence.segment_length(parsed)), [:rst, :ack]}
    end
  end

  defp passive_connection_state(opts) do
    %{
      listener: listener,
      src_addr: src_addr,
      dst_addr: dst_addr,
      src_port: src_port,
      dst_port: dst_port,
      segment: segment,
      link: link,
      mtu: mtu,
      socket_opts: socket_opts
    } = opts

    %{seq: seq, window: window, options: options} = Tcp.parse_segment(segment)
    iss = :crypto.strong_rand_bytes(4) |> :binary.decode_unsigned()
    recv_buffer_size = configured_recv_buffer_size(socket_opts)

    {rcv_wnd_scale, snd_wnd_scale, window_scaling_negotiated} =
      negotiated_window_scaling(options, window_scale_for(recv_buffer_size))

    local_mss = local_send_mss(mtu)

    %__MODULE__{
      pair: {{dst_addr, dst_port}, {src_addr, src_port}},
      link: link,
      socket_opts: socket_opts,
      tcb: %Tcb{
        iss: iss,
        snd_una: iss,
        snd_nxt: Sequence.wrap(iss + 1),
        # The window in the initial SYN is never scaled.
        snd_wnd: window,
        irs: seq,
        rcv_nxt: Sequence.wrap(seq + 1),
        rcv_wnd: min(recv_buffer_size, @max_window),
        rcv_adv_wnd: min(recv_buffer_size, @max_window),
        rcv_right_edge: Sequence.wrap(seq + 1 + min(recv_buffer_size, @max_window)),
        rcv_mss: local_mss,
        snd_mss: peer_send_mss(options, local_mss),
        rcv_wnd_scale: rcv_wnd_scale,
        snd_wnd_scale: snd_wnd_scale,
        window_scaling_negotiated: window_scaling_negotiated
      },
      recv_buffer_size: recv_buffer_size,
      rto_ms: @initial_rto_ms,
      soft_error: nil,
      syn_retransmit_count: 0,
      fin_wait_2_timeout_ms: configured_fin_wait_2_timeout_ms(socket_opts),
      challenge_ack_limiter: configured_challenge_ack_limiter(socket_opts),
      passive_listener: listener
    }
  end

  defp listen_addr_matches?(<<0::128>>, _dst_addr), do: true
  defp listen_addr_matches?(local_addr, dst_addr), do: local_addr == dst_addr

  defp listen_backlog_full?(listen_data) do
    listen_data.pending_count + length(listen_data.accept_queue) >= listen_data.backlog
  end

  defp passive_link(peer_addr, local_addr) do
    case Application.lookup_link(peer_addr) do
      {link, {^local_addr, mtu}} -> {:ok, link, mtu}
      _ -> :error
    end
  end

  defp passive_connection_opts(
         listen_data,
         src_addr,
         dst_addr,
         src_port,
         dst_port,
         segment
       ) do
    with true <- listen_addr_matches?(listen_data.local_addr, dst_addr),
         false <- listen_backlog_full?(listen_data),
         {:ok, link, mtu} <- passive_link(src_addr, dst_addr) do
      {:ok,
       %{
         listener: self(),
         src_addr: src_addr,
         dst_addr: dst_addr,
         src_port: src_port,
         dst_port: dst_port,
         segment: segment,
         link: link,
         mtu: mtu,
         socket_opts: listen_data.socket_opts
       }}
    else
      _ -> :ignore
    end
  end

  defp start_passive_child(listen_data, opts) do
    case start_passive_connection(opts) do
      {:ok, child} ->
        ref = Process.monitor(child)

        new_data =
          listen_data
          |> Map.put(:pending_count, listen_data.pending_count + 1)
          |> put_child(child, ref, :pending)

        send(child, :send_syn_ack)
        {:keep_state, new_data}

      _ ->
        :keep_state_and_data
    end
  end

  defp connect_from_closed(from, timeout, closed_data, dst_addr, dst_port) do
    case Application.lookup_link(dst_addr) do
      {link, {src_addr, mtu}} ->
        start_closed_connection(
          from,
          timeout,
          closed_data,
          link,
          src_addr,
          mtu,
          dst_addr,
          dst_port
        )

      nil ->
        {:keep_state_and_data, {:reply, from, {:error, :enetunreach}}}
    end
  end

  defp start_closed_connection(
         from,
         timeout,
         closed_data,
         link,
         src_addr,
         mtu,
         dst_addr,
         dst_port
       ) do
    case allocate_port(src_addr, {dst_addr, dst_port}) do
      {:ok, pair} ->
        state = connection_state(pair, link, mtu, closed_data)
        send_syn = {:next_event, :internal, {:send_syn, from, timeout}}
        {:next_state, :closed, state, send_syn}

      {:error, reason} ->
        {:keep_state_and_data, {:reply, from, {:error, reason}}}
    end
  end

  defp connect_from_bound(from, timeout, bound_data, dst_addr, dst_port) do
    case Application.lookup_link(dst_addr) do
      {link, {src_addr, mtu}} ->
        start_bound_connection(from, timeout, bound_data, link, src_addr, mtu, dst_addr, dst_port)

      nil ->
        {:keep_state_and_data, {:reply, from, {:error, :enetunreach}}}
    end
  end

  defp start_bound_connection(from, timeout, bound_data, link, src_addr, mtu, dst_addr, dst_port) do
    with {:ok, local_addr} <- bound_connect_source(bound_data.local_addr, src_addr),
         :ok <-
           Application.register_socket_pair(
             {{local_addr, bound_data.local_port}, {dst_addr, dst_port}}
           ) do
      pair = {{local_addr, bound_data.local_port}, {dst_addr, dst_port}}
      state = connection_state(pair, link, mtu, bound_data)
      send_syn = {:next_event, :internal, {:send_syn, from, timeout}}

      deregister_bound_data(bound_data)
      {:next_state, :closed, state, send_syn}
    else
      {:error, :eaddrnotavail} ->
        {:keep_state_and_data, {:reply, from, {:error, :eaddrnotavail}}}

      {:error, {:already_registered, _pid}} ->
        {:keep_state_and_data, {:reply, from, {:error, :eaddrinuse}}}
    end
  end

  defp connection_state(pair, link, mtu, data) do
    recv_buffer_size = recv_buffer_size(data)
    socket_opts = connection_socket_opts(data)

    %__MODULE__{
      pair: pair,
      link: link,
      socket_opts: socket_opts,
      tcb: %Tcb{
        rcv_mss: local_send_mss(mtu),
        rcv_wnd: recv_buffer_size,
        rcv_wnd_scale: window_scale_for(recv_buffer_size)
      },
      soft_error: nil,
      recv_buffer_size: recv_buffer_size,
      fin_wait_2_timeout_ms: fin_wait_2_timeout_ms(data),
      challenge_ack_limiter: challenge_ack_limiter(data)
    }
  end

  defp put_child(listen_data, child, ref, status) do
    %{listen_data | children: Map.put(listen_data.children, child, {ref, status})}
  end

  defp remove_listen_child(listen_data, child) do
    case Map.pop(listen_data.children, child) do
      {{ref, :pending}, children} ->
        Process.demonitor(ref, [:flush])

        %{
          listen_data
          | children: children,
            pending_count: max(0, listen_data.pending_count - 1)
        }

      {{ref, :queued}, children} ->
        Process.demonitor(ref, [:flush])

        %{
          listen_data
          | children: children,
            accept_queue: List.delete(listen_data.accept_queue, child)
        }

      {nil, _children} ->
        listen_data
    end
  end

  defp enqueue_accepted_child(%{accept_waiters: [{from, _ref, timer_ref} | rest]} = data, child) do
    cancel_actions = if timer_ref, do: [{{:timeout, timer_ref}, :cancel}], else: []

    {data, _actions} =
      data
      |> Map.put(:accept_waiters, rest)
      |> accept_child(child)

    {data, cancel_actions ++ [{:reply, from, {:ok, child}}]}
  end

  defp enqueue_accepted_child(%{accept_selects: selects} = data, child) when selects != [] do
    notify_selects(selects)

    data =
      data
      |> Map.put(:accept_queue, data.accept_queue ++ [child])
      |> Map.put(:accept_selects, [])

    {data, []}
  end

  defp enqueue_accepted_child(data, child) do
    {%{data | accept_queue: data.accept_queue ++ [child]}, []}
  end

  defp accept_child(data, child, actions \\ []) do
    case Map.pop(data.children, child) do
      {{ref, _status}, children} ->
        Process.demonitor(ref, [:flush])
        {%{data | children: children}, actions}

      {nil, _children} ->
        {data, actions}
    end
  end

  defp close_accept_actions(data) do
    notify_selects(data.accept_selects)

    Enum.flat_map(data.accept_waiters, fn {from, _ref, timer_ref} ->
      actions = [{:reply, from, {:error, :closed}}]

      if timer_ref do
        [{{:timeout, timer_ref}, :cancel} | actions]
      else
        actions
      end
    end)
  end

  defp deregister_bound_data(data) do
    Application.deregister_bound_socket(data.local_addr, data.local_port)
  end

  defp deregister_listen_data(data) do
    Enum.each(data.children, fn {child, {ref, _status}} ->
      Process.demonitor(ref, [:flush])
      Process.exit(child, :shutdown)
    end)

    Application.deregister_listener(data.local_addr, data.local_port)
    deregister_bound_data(data)
  end

  defp send_syn_ack(%__MODULE__{} = state) do
    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    options =
      if state.tcb.window_scaling_negotiated do
        [mss: state.tcb.rcv_mss, window_scale: state.tcb.rcv_wnd_scale]
      else
        [mss: state.tcb.rcv_mss]
      end

    tcp_segment =
      Tcp.build_segment(
        state.pair,
        state.tcb.iss,
        state.tcb.rcv_nxt,
        [:syn, :ack],
        advertised_syn_window(state),
        options
      )

    packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
    :ok = Tricep.Link.send(state.link, packet)
  end

  defp retransmit_syn_ack(%__MODULE__{} = state) do
    send_syn_ack(state)

    new_rto = min(state.rto_ms * 2, @max_rto_ms)

    new_state = %{
      state
      | syn_retransmit_count: state.syn_retransmit_count + 1,
        rto_ms: new_rto
    }

    {:keep_state, new_state, {{:timeout, :rto}, new_rto, :syn_ack_timeout}}
  end

  defp notify_passive_listener(
         %__MODULE__{passive_listener: listener},
         {:passive_failed, reason}
       )
       when is_pid(listener) do
    send(listener, {:passive_failed, self(), reason})
  end

  defp notify_passive_listener(%__MODULE__{passive_listener: listener}, message)
       when is_pid(listener) do
    send(listener, {message, self()})
  end

  defp notify_passive_listener(%__MODULE__{}, _message), do: :ok

  defp retransmit_syn(state, timeout_event) do
    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(state.pair, state.tcb.iss, 0, [:syn], advertised_syn_window(state),
        mss: state.tcb.rcv_mss,
        window_scale: state.tcb.rcv_wnd_scale
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
      reset_connection(state, retry_exhaustion_error(state))
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
      reset_connection(state, retry_exhaustion_error(state))
    else
      # Retransmit the oldest unacked segment
      {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

      tcp_segment =
        Tcp.build_segment(
          state.pair,
          seq,
          state.tcb.rcv_nxt,
          [:ack, :psh],
          Tcb.advertised_receive_window(state.tcb),
          payload: payload
        )

      packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
      Tricep.Link.send(state.link, packet)

      # Update segment with incremented retransmit count
      updated_entry = {seq, Sequence.wrap(seq + byte_size(payload)), payload, count + 1}
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

  defp retry_exhaustion_error(%__MODULE__{soft_error: error})
       when is_atom(error) and not is_nil(error),
       do: error

  defp retry_exhaustion_error(%__MODULE__{}), do: :etimedout

  defp handle_recv_call(%__MODULE__{} = state, from, length, timeout) do
    case deliver_data(state.recv_buffer, length) do
      {:ok, data, rest} ->
        new_state =
          state
          |> Map.put(:recv_buffer, rest)
          |> refresh_receive_window()
          |> maybe_send_window_update(state)

        {:keep_state, new_state, {:reply, from, {:ok, data}}}

      :wait ->
        cond do
          state.fin_received ->
            handle_final_recv_call(state, from, length)

          state.read_shutdown ->
            {:keep_state_and_data, {:reply, from, {:error, :closed}}}

          true ->
            wait_for_recv_data(state, from, length, timeout)
        end
    end
  end

  defp wait_for_recv_data(%__MODULE__{} = state, from, length, timeout) do
    case timeout do
      :nowait ->
        ref = make_ref()
        {caller_pid, _} = from

        new_state = %{
          state
          | recv_selects: state.recv_selects ++ [{caller_pid, ref, length}]
        }

        {:keep_state, new_state, {:reply, from, {:select, {:select_info, :recv, ref}}}}

      :infinity ->
        timer_ref = make_ref()
        waiter = {from, length, timer_ref}
        new_state = %{state | recv_waiters: state.recv_waiters ++ [waiter]}
        {:keep_state, new_state}

      ms when is_integer(ms) ->
        timer_ref = make_ref()
        waiter = {from, length, timer_ref}
        new_state = %{state | recv_waiters: state.recv_waiters ++ [waiter]}
        actions = [{{:timeout, timer_ref}, ms, {:recv_timeout, timer_ref}}]
        {:keep_state, new_state, actions}
    end
  end

  defp handle_recv_timeout(%__MODULE__{} = state, timer_ref) do
    case List.keytake(state.recv_waiters, timer_ref, 2) do
      {{from, _length, ^timer_ref}, rest} ->
        new_state = %{state | recv_waiters: rest}
        {:keep_state, new_state, {:reply, from, {:error, :timeout}}}

      nil ->
        :keep_state_and_data
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

  defp settle_close_waiters(%__MODULE__{} = state) do
    {state, recv_actions} =
      if state.read_shutdown do
        notify_selects(state.recv_selects)

        {recv_buffer, _recv_waiters, recv_actions} =
          process_waiters_eof(state.recv_buffer, state.recv_waiters)

        new_state = %{
          state
          | recv_buffer: recv_buffer,
            recv_waiters: [],
            recv_selects: []
        }

        {new_state, recv_actions}
      else
        {state, []}
      end

    send_actions = notify_send_waiters_error(state.send_waiters, :epipe)

    new_state =
      state
      |> Map.put(:send_waiters, [])
      |> refresh_receive_window()

    {new_state, recv_actions ++ send_actions}
  end

  defp do_flush_send_buffer(%__MODULE__{} = state) do
    available = Tcb.send_window_available(state.tcb)

    cond do
      DataBuffer.empty?(state.send_buffer) ->
        keep_state_sync_persist(state)

      available <= 0 ->
        keep_state_sync_persist(state)

      true ->
        # Take only bytes the peer's advertised receive window currently permits.
        mss = state.tcb.snd_mss || @default_mss
        send_len = min(mss, available)
        {payload_iodata, new_send_buffer} = DataBuffer.take(state.send_buffer, send_len)
        payload = IO.iodata_to_binary(payload_iodata)

        seq_start = state.tcb.snd_nxt
        seq_end = Sequence.wrap(seq_start + byte_size(payload))

        {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

        tcp_segment =
          Tcp.build_segment(
            state.pair,
            seq_start,
            state.tcb.rcv_nxt,
            [:ack, :psh],
            Tcb.advertised_receive_window(state.tcb),
            payload: payload
          )

        packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
        Tricep.Link.send(state.link, packet)

        # Track segment for retransmission: {seq_start, seq_end, payload, retransmit_count}
        unacked_entry = {seq_start, seq_end, payload, 0}
        new_unacked = state.unacked_segments ++ [unacked_entry]

        new_state = %{
          state
          | tcb: Tcb.advance_send(state.tcb, byte_size(payload)),
            send_buffer: new_send_buffer,
            unacked_segments: new_unacked
        }

        actions =
          new_state
          |> schedule_flush_send_buffer([])
          |> schedule_pending_fin(new_state)

        {new_state, actions} = sync_persist_timer(new_state, actions)

        # Start RTO timer if not already running
        {new_state, actions} =
          if state.rto_timer_active do
            {new_state, actions}
          else
            {%{new_state | rto_timer_active: true},
             [{{:timeout, :rto}, state.rto_ms, :retransmit} | actions]}
          end

        {:keep_state, new_state, actions}
    end
  end

  defp reset_state(%__MODULE__{} = state) do
    Application.deregister_socket_pair(state.pair)
  end

  defp closed_data(%__MODULE__{socket_opts: socket_opts}), do: %{socket_opts: socket_opts}

  # RFC 5927 section 4.1 recommends accepting ICMP errors only when their
  # quoted TCP sequence falls within SND.UNA =< SEG.SEQ < SND.NXT. During the
  # handshake the only in-flight segment is the SYN or SYN-ACK, so require
  # both its exact sequence and the SYN control bit.
  defp applicable_icmpv6_quote?(
         %{seq: sequence, syn?: true},
         {:syn_sent, _from},
         %__MODULE__{tcb: %Tcb{iss: iss} = tcb}
       ) do
    sequence == iss and Tcb.in_flight?(tcb, sequence)
  end

  defp applicable_icmpv6_quote?(
         %{seq: sequence, syn?: true},
         :syn_received,
         %__MODULE__{tcb: %Tcb{iss: iss} = tcb}
       ) do
    sequence == iss and Tcb.in_flight?(tcb, sequence)
  end

  defp applicable_icmpv6_quote?(%{seq: sequence}, state_name, %__MODULE__{tcb: tcb})
       when state_name in [
              :established,
              :close_wait,
              :fin_wait_1,
              :fin_wait_2,
              :closing,
              :last_ack
            ] do
    Tcb.in_flight?(tcb, sequence)
  end

  defp applicable_icmpv6_quote?(_quoted_tcp, _state_name, _state), do: false

  defp apply_icmpv6_error({:packet_too_big, mtu}, state_name, %__MODULE__{} = state)
       when state_name in [:established, :close_wait] do
    {new_state, actions} = apply_path_mtu(state, mtu)
    {:keep_state, new_state, actions}
  end

  defp apply_icmpv6_error({:packet_too_big, mtu}, state_name, %__MODULE__{} = state)
       when state_name in [:fin_wait_1, :fin_wait_2, :closing, :last_ack] do
    {new_state, _actions} = apply_path_mtu(state, mtu)
    {:keep_state, new_state}
  end

  defp apply_icmpv6_error({:hard, reason}, {:syn_sent, from}, %__MODULE__{} = state)
       when is_tuple(from) do
    Logger.debug("Applying ICMPv6 hard error #{inspect(reason)} during active handshake")
    reset_state(state)

    actions = [
      {{:timeout, :rto}, :cancel},
      {{:timeout, :connect_timeout}, :cancel},
      {:reply, from, {:error, reason}}
    ]

    {:next_state, :closed, closed_data(state), actions}
  end

  defp apply_icmpv6_error({:hard, reason}, {:syn_sent, :nowait}, %__MODULE__{} = state) do
    Logger.debug("Applying ICMPv6 hard error #{inspect(reason)} during active handshake")
    {state_name, state_data} = nowait_connect_failure(state, reason)
    {:next_state, state_name, state_data, {{:timeout, :rto}, :cancel}}
  end

  defp apply_icmpv6_error({:soft, reason}, {:syn_sent, _from}, %__MODULE__{} = state) do
    Logger.debug("Recording ICMPv6 soft error #{inspect(reason)} during active handshake")
    {:keep_state, %{state | soft_error: reason}}
  end

  defp apply_icmpv6_error({classification, reason}, :syn_received, %__MODULE__{} = state)
       when classification in [:hard, :soft] do
    # The SYN-ACK remains subject to the existing retransmission budget. Do
    # not let an unauthenticated ICMPv6 error tear down the pending child.
    Logger.debug("Recording ICMPv6 soft error #{inspect(reason)} during passive handshake")
    {:keep_state, %{state | soft_error: reason}}
  end

  defp apply_icmpv6_error({classification, reason}, state_name, %__MODULE__{} = state)
       when classification in [:hard, :soft] and
              state_name in [
                :established,
                :close_wait,
                :fin_wait_1,
                :fin_wait_2,
                :closing,
                :last_ack
              ] do
    # RFC 5927 section 5.2: synchronized connections treat matching ICMP
    # destination-unreachable, time-exceeded, and parameter-problem reports
    # as soft errors. TCP retransmission remains responsible for failure. A
    # TCP user-timeout/keepalive liveness policy is owned by #130. Idle
    # connections intentionally do not accept four-tuple-only ICMP errors.
    Logger.debug("Recording ICMPv6 soft error #{inspect(reason)} in #{state_name} state")
    {:keep_state, %{state | soft_error: reason}}
  end

  defp apply_icmpv6_error(_event, _state_name, _state), do: :keep_state_and_data

  defp reset_connection(%__MODULE__{} = state, error, timer_actions \\ []) do
    # A reset tears down states that may own a named RTO. gen_statem cancellation
    # removes its queued delivery; a missed cancellation must fail loudly rather
    # than being absorbed after closure.
    reset_state(state)
    actions = [{{:timeout, :rto}, :cancel} | timer_actions] ++ notify_waiters_error(state, error)
    {:next_state, :closed, closed_data(state), actions}
  end

  defp synchronized_rejection(state, outcome, reset \\ :connection)

  defp synchronized_rejection(_state, :malformed, _reset), do: :keep_state_and_data

  defp synchronized_rejection(state, :acceptable_reset, :connection) do
    reset_connection(state, :econnreset)
  end

  defp synchronized_rejection(state, :acceptable_reset, {:connection, timer_actions}) do
    reset_connection(state, :econnreset, timer_actions)
  end

  defp synchronized_rejection(state, :acceptable_reset, :close) do
    # CLOSING and LAST_ACK reach this path only after their send buffer and
    # close waiters are settled, so no persist timer or caller remains. The
    # unacknowledged FIN may still own an RTO and is cancelled explicitly.
    reset_state(state)
    {:next_state, :closed, closed_data(state), {{:timeout, :rto}, :cancel}}
  end

  defp synchronized_rejection(state, :challenge_ack, _reset), do: send_challenge_ack(state)

  defp synchronized_rejection(_state, :silent_drop, _reset), do: :keep_state_and_data

  # RFC 5961 RST/SYN challenge ACKs use one shared limiter. Issue #124 owns
  # the separate policy for non-RFC-5961 corrective ACKs.
  defp synchronized_rejection(state, :unacceptable_segment, _reset),
    do: reject_unacceptable_segment(state)

  defp synchronized_rejection(state, :invalid_ack, _reset), do: reject_invalid_ack(state)

  defp syn_sent_segment(state, segment) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, ack: acknowledgment} = parsed ->
        syn_sent_outcome(state, parsed, flags, acknowledgment)

      _ ->
        :ignore
    end
  end

  defp syn_sent_outcome(state, parsed, flags, acknowledgment) do
    if :rst in flags do
      syn_sent_reset_outcome(state.tcb, flags, acknowledgment)
    else
      syn_sent_non_reset_outcome(state, parsed, flags, acknowledgment)
    end
  end

  defp syn_sent_reset_outcome(tcb, flags, acknowledgment) do
    if :ack in flags and acknowledges_syn?(tcb, acknowledgment), do: :reset, else: :ignore
  end

  defp syn_sent_non_reset_outcome(state, parsed, flags, acknowledgment) do
    case {:syn in flags, :ack in flags, acknowledgment == state.tcb.snd_nxt} do
      {true, true, true} -> {:established, establish_after_syn_ack(state, parsed)}
      {_syn?, true, false} -> {:bad_ack, acknowledgment}
      _ -> :ignore
    end
  end

  defp syn_received_segment(state, segment) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: sequence, ack: acknowledgment, window: window, payload: payload} ->
        syn_received_outcome(state, flags, sequence, acknowledgment, window, payload)

      _ ->
        :ignore
    end
  end

  defp syn_received_outcome(state, flags, sequence, acknowledgment, window, payload) do
    if :rst in flags do
      Synchronized.reset_outcome(state.tcb, sequence)
    else
      syn_received_non_reset_outcome(state, flags, sequence, acknowledgment, window, payload)
    end
  end

  defp syn_received_non_reset_outcome(state, flags, sequence, acknowledgment, window, payload) do
    cond do
      :syn in flags and sequence == state.tcb.irs ->
        :retransmit_syn_ack

      not Tcb.acceptable_segment?(state.tcb, %{flags: flags, seq: sequence, payload: payload}) ->
        :unacceptable_segment

      :ack in flags and acknowledges_syn_ack?(state.tcb, acknowledgment) ->
        {next_state, new_state, receive_actions} =
          establish_after_syn_received(state, flags, sequence, acknowledgment, window, payload)

        {:established, next_state, new_state, receive_actions}

      :ack in flags ->
        {:bad_ack, acknowledgment}

      true ->
        :ignore
    end
  end

  defp establish_after_syn_received(state, flags, sequence, acknowledgment, window, payload) do
    base_state =
      %{
        state
        | tcb: Tcb.acknowledge(state.tcb, acknowledgment, window),
          syn_retransmit_count: 0,
          rto_ms: @initial_rto_ms,
          soft_error: nil,
          passive_listener: nil
      }
      |> open_receive_window()

    receive_syn_received_segment(base_state, sequence, payload, flags)
  end

  defp establish_after_syn_ack(state, %{
         seq: sequence,
         ack: acknowledgment,
         window: window,
         options: options
       }) do
    send_mss = peer_send_mss(options, state.tcb.rcv_mss)

    {receive_window_scale, send_window_scale, window_scaling_negotiated} =
      negotiated_window_scaling(options, state.tcb.rcv_wnd_scale)

    %{
      state
      | tcb:
          Tcb.establish_active(
            state.tcb,
            %{
              initial_receive_sequence: sequence,
              acknowledgment: acknowledgment,
              send_window: window,
              send_mss: send_mss,
              receive_window_scale: receive_window_scale,
              send_window_scale: send_window_scale,
              window_scaling_negotiated: window_scaling_negotiated
            }
          ),
        syn_retransmit_count: 0,
        rto_ms: @initial_rto_ms,
        soft_error: nil
    }
    |> open_receive_window()
  end

  defp acknowledges_syn?(%Tcb{iss: iss, snd_nxt: send_next}, acknowledgment) do
    Sequence.gt?(acknowledgment, iss) and Sequence.lte?(acknowledgment, send_next)
  end

  defp acknowledges_syn_ack?(
         %Tcb{snd_una: send_unacknowledged, snd_nxt: send_next},
         acknowledgment
       ) do
    Sequence.gt?(acknowledgment, send_unacknowledged) and
      Sequence.lte?(acknowledgment, send_next)
  end

  defp receive_syn_received_segment(state, sequence, payload, flags) do
    if payload == <<>> and :fin not in flags do
      # Preserve the passive handshake's existing ACK scheduling: the final
      # bare ACK establishes the child without emitting an extra packet.
      {:established, state, []}
    else
      {receive_state, _delivered_length, fin_ready?} =
        receive_segment(state, sequence, payload, flags)

      receive_state = refresh_receive_window(receive_state)

      send_ack(receive_state.tcb.rcv_nxt, receive_state)

      if fin_ready? do
        {receive_state, eof_actions} = deliver_receive_eof(receive_state)
        {:close_wait, receive_state, eof_actions}
      else
        {:established, receive_state, []}
      end
    end
  end

  defp transition_after_received_fin(state, next_state, actions, extra_actions \\ []) do
    {new_state, eof_actions} = deliver_receive_eof(state)

    send_ack(new_state.tcb.rcv_nxt, new_state)
    {:next_state, next_state, new_state, actions ++ eof_actions ++ extra_actions}
  end

  defp peer_send_mss(options, local_mss) do
    peer_mss =
      case options do
        %{mss: mss} when is_integer(mss) -> max(mss, @minimum_snd_mss)
        _options -> @default_mss
      end

    min(peer_mss, min(local_mss, @maximum_ipv6_tcp_mss))
  end

  defp local_send_mss(mtu) when is_integer(mtu) and mtu >= @ipv6_min_mtu do
    min(mtu - @tcp_ipv6_header_size, @maximum_ipv6_tcp_mss)
  end

  defp nowait_connect_failure(%__MODULE__{} = state, reason) do
    reset_state(state)
    closed_data = closed_data(state)

    case state.connect_selects do
      [] ->
        {:closed, closed_data}

      connect_selects ->
        notify_selects(connect_selects)
        {{:connect_failed, connect_selects, reason}, closed_data}
    end
  end

  defp send_ack(ack_num, %__MODULE__{} = state) do
    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(
        state.pair,
        state.tcb.snd_nxt,
        ack_num,
        [:ack],
        Tcb.advertised_receive_window(state.tcb)
      )

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
    seq_start = state.tcb.snd_nxt
    seq_end = Sequence.wrap(seq_start + 1)

    send_fin_segment(state, seq_start)

    new_state = %{
      state
      | tcb: Tcb.advance_send(state.tcb, 1),
        unacked_segments: state.unacked_segments ++ [{seq_start, seq_end, :fin, 0}]
    }

    if state.rto_timer_active do
      {new_state, []}
    else
      {%{new_state | rto_timer_active: true}, [{{:timeout, :rto}, state.rto_ms, :retransmit}]}
    end
  end

  defp close_or_drain_send_buffer(%__MODULE__{} = state, from, next_state) do
    {state, waiter_actions} = settle_close_waiters(state)

    if DataBuffer.empty?(state.send_buffer) do
      {state, waiter_actions} = sync_persist_timer(state, waiter_actions)
      {new_state, actions} = send_fin_and_track(%{state | write_shutdown: false})
      {:next_state, next_state, new_state, [{:reply, from, :ok}] ++ waiter_actions ++ actions}
    else
      new_state = %{state | write_shutdown: true}

      {:keep_state, new_state,
       waiter_actions ++ [{:reply, from, :ok}, {:next_event, :internal, :flush_send_buffer}]}
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
        state.tcb.rcv_nxt,
        [:fin, :ack],
        Tcb.advertised_receive_window(state.tcb)
      )

    packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
    Tricep.Link.send(state.link, packet)
  end

  defp bound_connect_source(@any_addr, route_srcaddr), do: {:ok, route_srcaddr}
  defp bound_connect_source(addr, addr), do: {:ok, addr}
  defp bound_connect_source(_bound_addr, _route_srcaddr), do: {:error, :eaddrnotavail}

  defp bind_local_socket(local_addr, 0), do: allocate_bound_port(local_addr)

  defp bind_local_socket(local_addr, local_port) do
    case Application.register_bound_socket(local_addr, local_port) do
      :ok -> {:ok, local_port}
      {:error, {:already_registered, _pid}} -> {:error, :eaddrinuse}
    end
  end

  defp allocate_bound_port(local_addr) do
    start_offset = System.unique_integer([:positive, :monotonic]) |> rem(@ephemeral_port_count)
    allocate_bound_port(local_addr, start_offset, 0)
  end

  defp allocate_bound_port(_local_addr, _start_offset, attempts)
       when attempts >= @ephemeral_port_count do
    {:error, :eaddrnotavail}
  end

  defp allocate_bound_port(local_addr, start_offset, attempts) do
    port = @ephemeral_port_first + rem(start_offset + attempts, @ephemeral_port_count)

    case Application.register_bound_socket(local_addr, port) do
      :ok ->
        {:ok, port}

      {:error, {:already_registered, _pid}} ->
        allocate_bound_port(local_addr, start_offset, attempts + 1)
    end
  end

  defp allocate_port(srcaddr_bin, dst) do
    start_offset = System.unique_integer([:positive, :monotonic]) |> rem(@ephemeral_port_count)
    allocate_port(srcaddr_bin, dst, start_offset, 0)
  end

  defp allocate_port(_srcaddr_bin, _dst, _start_offset, attempts)
       when attempts >= @ephemeral_port_count do
    {:error, :eaddrnotavail}
  end

  defp allocate_port(srcaddr_bin, dst, start_offset, attempts) do
    port = @ephemeral_port_first + rem(start_offset + attempts, @ephemeral_port_count)
    pair = {{srcaddr_bin, port}, dst}

    case Application.register_socket_pair(pair) do
      :ok ->
        {:ok, pair}

      _ ->
        allocate_port(srcaddr_bin, dst, start_offset, attempts + 1)
    end
  end

  # --- Helper functions ---

  defp validate_sockaddr_in6(address), do: validate_sockaddr_in6(address, 1..65_535)

  defp validate_sockaddr_in6(%{family: :inet6, addr: addr, port: port}, port_range) do
    with true <- is_integer(port) and port in port_range,
         {:ok, dstaddr_bin} <- valid_ipv6_address(addr) do
      {:ok, dstaddr_bin, port}
    else
      _ -> {:error, :einval}
    end
  end

  defp validate_sockaddr_in6(_address, _port_range), do: {:error, :einval}

  defp sockaddr_in6(addr, port) do
    %{family: :inet6, addr: ipv6_tuple(addr), port: port}
  end

  defp ipv6_tuple(<<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>) do
    {a, b, c, d, e, f, g, h}
  end

  defp valid_ipv6_address(addr) do
    Tricep.Address.from(addr)
  rescue
    FunctionClauseError -> {:error, :einval}
    ArgumentError -> {:error, :einval}
  end

  # Keep call sites focused on TCP state transitions; modular arithmetic lives
  # in the independently testable Sequence module.
  defp socket_opts(opts) when is_list(opts), do: Keyword.get(opts, :opts, %{})
  defp socket_opts(opts) when is_map(opts), do: opts
  defp socket_opts(_opts), do: %{}

  defp connection_socket_opts(%{socket_opts: socket_opts}), do: socket_opts
  defp connection_socket_opts(data), do: socket_opts(data)

  defp recv_buffer_size(%{socket_opts: opts}), do: configured_recv_buffer_size(opts)
  defp recv_buffer_size(_closed_data), do: @default_recv_buffer_size

  defp fin_wait_2_timeout_ms(%{socket_opts: opts}), do: configured_fin_wait_2_timeout_ms(opts)
  defp fin_wait_2_timeout_ms(_closed_data), do: @default_fin_wait_2_timeout_ms

  defp challenge_ack_limiter(%{socket_opts: opts}), do: configured_challenge_ack_limiter(opts)
  defp challenge_ack_limiter(_closed_data), do: ChallengeAckLimiter.new()

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

  defp configured_challenge_ack_limiter(opts) when is_map(opts) do
    ChallengeAckLimiter.new(
      limit: Map.get(opts, :challenge_ack_limit, 10),
      interval_ms: Map.get(opts, :challenge_ack_interval_ms, 5_000)
    )
  end

  defp configured_challenge_ack_limiter(opts) when is_list(opts) do
    ChallengeAckLimiter.new(
      limit: Keyword.get(opts, :challenge_ack_limit, 10),
      interval_ms: Keyword.get(opts, :challenge_ack_interval_ms, 5_000)
    )
  end

  defp configured_challenge_ack_limiter(_opts), do: ChallengeAckLimiter.new()

  defp normalize_recv_buffer_size(size) when is_integer(size) and size > 0 do
    min(size, @max_scaled_tcp_window)
  end

  defp normalize_recv_buffer_size(_size), do: @default_recv_buffer_size

  defp normalize_fin_wait_2_timeout_ms(timeout_ms)
       when is_integer(timeout_ms) and timeout_ms > 0 do
    timeout_ms
  end

  defp normalize_fin_wait_2_timeout_ms(_timeout_ms), do: @default_fin_wait_2_timeout_ms

  # Bug #125 owns making legacy socket-option validation uniform. Keep the
  # RFC 5961 limiter strict without changing legacy fallback behavior here.
  defp valid_socket_options?(opts), do: ChallengeAckLimiter.valid_options?(opts)

  defp available_receive_window(%__MODULE__{} = state) do
    max(0, application_receive_capacity(state) - out_of_order_size(state))
  end

  # Keep up to one locally advertised MSS out of the reassembly queue. This
  # prevents out-of-order data from consuming the last bytes of the advertised
  # window before a receive-front retransmission can be admitted. If unread
  # in-order data already fills the application buffer, zero window remains
  # the correct TCP behavior.
  defp out_of_order_byte_budget(%__MODULE__{} = state) do
    application_capacity = application_receive_capacity(state)
    front_recovery_reserve = min(application_capacity, state.tcb.rcv_mss || @default_mss)
    application_capacity - front_recovery_reserve
  end

  defp application_receive_capacity(%__MODULE__{} = state) do
    max(0, state.recv_buffer_size - byte_size(state.recv_buffer))
  end

  defp advertised_syn_window(%__MODULE__{} = state) do
    state
    |> available_receive_window()
    |> min(@max_window)
  end

  defp open_receive_window(%__MODULE__{} = state) do
    # Leave one scale quantum of physical headroom for sub-quantum ACK movement.
    refresh_receive_window(state, reserve_scale_headroom?: true)
  end

  defp refresh_receive_window(%__MODULE__{} = state, opts \\ []) do
    %{state | tcb: Tcb.refresh_receive_window(state.tcb, available_receive_window(state), opts)}
  end

  defp receive_window(%__MODULE__{} = state) do
    Tcb.receive_window(state.tcb, available_receive_window(state))
  end

  defp maybe_send_window_update(%__MODULE__{} = new_state, %__MODULE__{} = old_state) do
    if Tcb.advertised_receive_window(new_state.tcb) >
         Tcb.advertised_receive_window(old_state.tcb) do
      send_ack(new_state.tcb.rcv_nxt, new_state)
    end

    new_state
  end

  defp receive_segment(%__MODULE__{} = state, sequence, payload, flags) do
    %{
      delivered: delivered,
      evicted_count: evicted_count,
      fin?: fin?,
      pending_fin: pending_fin,
      out_of_order_segments: segments,
      rcv_nxt: receive_next
    } =
      ReceiveReassembly.receive(
        state.out_of_order_segments,
        pending_fin_hint(state),
        state.tcb.rcv_nxt,
        receive_window(state),
        out_of_order_byte_budget(state),
        %{flags: flags, payload: payload, seq: sequence}
      )

    new_state = %{
      state
      | recv_buffer: state.recv_buffer <> delivered,
        out_of_order_segments: segments,
        out_of_order_fin: pending_fin_sequence(pending_fin),
        out_of_order_fin_payload_start: pending_fin_payload_start(pending_fin),
        tcb: Tcb.receive_next(state.tcb, receive_next)
    }

    new_state = record_reassembly_evictions(new_state, evicted_count)

    {new_state, byte_size(delivered), fin?}
  end

  defp record_reassembly_evictions(state, 0), do: state

  defp record_reassembly_evictions(%__MODULE__{} = state, evicted_count) do
    previous = state.reassembly_eviction_count
    total = previous + evicted_count

    log_reassembly_evictions(previous, total, evicted_count)

    %{state | reassembly_eviction_count: total}
  end

  # Emit the first eviction and later powers-of-two samples at debug level.
  # A hostile peer therefore cannot turn eviction-per-packet traffic into
  # unbounded operator-visible log volume.
  defp log_reassembly_evictions(previous, total, evicted_count) do
    if reassembly_eviction_log_due?(previous, total) do
      Logger.debug(
        "TCP receive reassembly evicted #{evicted_count} chunk(s); " <>
          "cumulative eviction count is #{total}"
      )
    end
  end

  defp reassembly_eviction_log_due?(0, _total), do: true

  defp reassembly_eviction_log_due?(previous, total) do
    length(Integer.digits(previous, 2)) < length(Integer.digits(total, 2))
  end

  defp pending_fin_hint(%__MODULE__{out_of_order_fin: nil}), do: nil

  defp pending_fin_hint(%__MODULE__{
         out_of_order_fin: sequence,
         out_of_order_fin_payload_start: payload_start
       }) do
    {sequence, payload_start || sequence}
  end

  defp pending_fin_sequence(nil), do: nil
  defp pending_fin_sequence({sequence, _payload_start}), do: sequence
  defp pending_fin_payload_start(nil), do: nil
  defp pending_fin_payload_start({_sequence, payload_start}), do: payload_start

  defp deliver_received_segment(%__MODULE__{} = state, sequence, payload, flags) do
    {receive_state, delivered_length, fin?} = receive_segment(state, sequence, payload, flags)
    receive_state = notify_recv_select(receive_state, delivered_length)

    {recv_buffer, recv_waiters, actions} =
      process_waiters(receive_state.recv_buffer, receive_state.recv_waiters)

    new_state =
      receive_state
      |> Map.put(:recv_buffer, recv_buffer)
      |> Map.put(:recv_waiters, recv_waiters)
      |> refresh_receive_window()

    {new_state, delivered_length, fin?, actions}
  end

  defp deliver_receive_eof(%__MODULE__{} = state) do
    receive_state = notify_recv_select(state, :eof)

    {recv_buffer, recv_waiters, actions} =
      process_waiters_eof(receive_state.recv_buffer, receive_state.recv_waiters)

    new_state =
      receive_state
      |> Map.put(:recv_buffer, recv_buffer)
      |> Map.put(:recv_waiters, recv_waiters)
      |> Map.put(:fin_received, true)
      |> refresh_receive_window()

    {new_state, actions}
  end

  defp out_of_order_size(%__MODULE__{out_of_order_segments: segments}) do
    Enum.reduce(segments, 0, fn {_seq, _seq_end, payload}, total ->
      total + byte_size(payload)
    end)
  end

  defp window_scale_for(size) when is_integer(size) and size > @max_window do
    Enum.find(1..@max_window_scale, @max_window_scale, fn scale ->
      size <= @max_window <<< scale
    end)
  end

  defp window_scale_for(_size), do: 0

  defp peer_window_scale(options) do
    options
    |> Map.get(:window_scale, 0)
    |> normalize_window_scale()
  end

  defp negotiated_window_scaling(options, rcv_wnd_scale) do
    if Map.has_key?(options, :window_scale) do
      {rcv_wnd_scale, peer_window_scale(options), true}
    else
      {0, 0, false}
    end
  end

  defp normalize_window_scale(scale) when is_integer(scale) and scale >= 0 do
    min(scale, @max_window_scale)
  end

  defp normalize_window_scale(_scale), do: 0

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

  defp persist_needed?(%__MODULE__{tcb: %Tcb{snd_wnd: 0}} = state), do: has_persist_data?(state)
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
        seq = Sequence.wrap(state.tcb.snd_nxt - 1)

        tcp_segment =
          Tcp.build_segment(
            state.pair,
            seq,
            state.tcb.rcv_nxt,
            [:ack, :psh],
            Tcb.advertised_receive_window(state.tcb),
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
    new_mss = path_mtu_mss(mtu)

    case Tcb.update_send_mss_for_path_mtu(state.tcb, new_mss, @default_mss) do
      {:reduced, tcb} ->
        Logger.info(
          "ICMPv6 Packet Too Big mtu=#{mtu} reduced TCP send MSS from #{state.tcb.snd_mss} to #{tcb.snd_mss}"
        )

        new_state = %{
          state
          | tcb: tcb,
            unacked_segments: resegment_unacked_segments(state.unacked_segments, new_mss)
        }

        actions = schedule_flush_send_buffer(new_state, [])
        {new_state, actions}

      :unchanged ->
        {state, []}
    end
  end

  defp apply_path_mtu(%__MODULE__{} = state, _mtu), do: {state, []}

  defp path_mtu_mss(mtu), do: max(@default_mss, mtu - @tcp_ipv6_header_size)

  defp resegment_unacked_segments(unacked_segments, mss) do
    Enum.flat_map(unacked_segments, fn
      {seq, _seq_end, payload, count} when is_binary(payload) ->
        resegment_payload(seq, payload, count, mss)

      segment ->
        [segment]
    end)
  end

  defp resegment_payload(_seq, <<>>, _count, _mss), do: []

  defp resegment_payload(seq, payload, count, mss) when byte_size(payload) <= mss do
    [{seq, Sequence.wrap(seq + byte_size(payload)), payload, count}]
  end

  defp resegment_payload(seq, payload, count, mss) do
    {chunk, rest} = split_binary(payload, mss)
    next_seq = Sequence.wrap(seq + byte_size(chunk))

    [{seq, next_seq, chunk, count} | resegment_payload(next_seq, rest, count, mss)]
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
    %{state | tcb: Tcb.update_send_window(state.tcb, window)}
    |> sync_persist_timer([])
  end

  defp process_ack_if_present(state, true, ack, window), do: process_ack(state, ack, window)

  defp reject_invalid_ack(state) do
    send_ack(state.tcb.rcv_nxt, state)
    {:keep_state, state, []}
  end

  defp send_challenge_ack(%__MODULE__{} = state) do
    now = System.monotonic_time(:millisecond)

    case ChallengeAckLimiter.allow(state.challenge_ack_limiter, now) do
      {:allow, limiter} ->
        send_ack(state.tcb.rcv_nxt, state)
        {:keep_state, %{state | challenge_ack_limiter: limiter}, []}

      {:limit, limiter} ->
        {:keep_state, %{state | challenge_ack_limiter: limiter}, []}
    end
  end

  defp handle_time_wait_segment(state, flags, sequence, payload_length) do
    cond do
      # RFC 1337 F1: an RST must not terminate TIME_WAIT; SYNs must not
      # trigger the narrow FIN retransmission exception either.
      :rst in flags or :syn in flags ->
        :keep_state_and_data

      :fin in flags and
          Sequence.wrap(sequence + payload_length) == Sequence.wrap(state.tcb.rcv_nxt - 1) ->
        # Re-ACK only the peer's FIN retransmission. Issue #104 owns any
        # TIME_WAIT timer-restart behavior.
        send_ack(state.tcb.rcv_nxt, state)
        :keep_state_and_data

      true ->
        # Avoid reflecting arbitrary old duplicates while retaining TIME_WAIT.
        :keep_state_and_data
    end
  end

  defp reject_unacceptable_segment(state) do
    send_ack(state.tcb.rcv_nxt, state)
    {:keep_state, state, []}
  end

  defp process_ack(state, ack, window) do
    cond do
      Sequence.gt?(ack, state.tcb.snd_nxt) ->
        send_ack(state.tcb.rcv_nxt, state)
        {state, []}

      Sequence.gt?(ack, state.tcb.snd_una) ->
        # ACK acknowledges new data - remove acknowledged segments from queue
        new_unacked =
          Enum.drop_while(state.unacked_segments, fn {_seq_start, seq_end, _payload, _count} ->
            Sequence.lte?(seq_end, ack)
          end)

        base_state = %{
          state
          | tcb: Tcb.acknowledge(state.tcb, ack, window),
            unacked_segments: new_unacked,
            rto_ms: @initial_rto_ms,
            soft_error: nil
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
        base_state = %{state | tcb: Tcb.update_send_window(state.tcb, window)}
        {new_state, send_waiter_actions} = process_send_waiters(base_state)
        send_waiter_actions = schedule_flush_send_buffer(new_state, send_waiter_actions)
        sync_persist_timer(new_state, send_waiter_actions)
    end
  end

  defp schedule_flush_send_buffer(state, actions) do
    flush_action = {:next_event, :internal, :flush_send_buffer}

    if not DataBuffer.empty?(state.send_buffer) and Tcb.send_window_available(state.tcb) > 0 and
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
    max(0, Tcb.send_window_available(state.tcb) - DataBuffer.size(state.send_buffer))
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

  defp deliver_final_data(buffer, length) do
    case deliver_data(buffer, length) do
      {:ok, data, rest} -> {data, rest}
      :wait -> {buffer, <<>>}
    end
  end

  defp handle_final_recv_call(%__MODULE__{} = state, from, length) do
    {data, rest} = deliver_final_data(state.recv_buffer, length)

    new_state =
      state
      |> Map.put(:recv_buffer, rest)
      |> refresh_receive_window()
      |> maybe_send_window_update(state)

    {:keep_state, new_state, {:reply, from, {:ok, data}}}
  end

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
    {data, new_buffer} = deliver_final_data(buffer, length)

    new_actions = [
      {:reply, from, {:ok, data}},
      {{:timeout, timer_ref}, :cancel}
    ]

    process_waiters_eof(new_buffer, rest, remaining_waiters, new_actions ++ actions)
  end
end
