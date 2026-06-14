defmodule Tricep.Socket do
  @moduledoc false

  @behaviour :gen_statem

  import Bitwise

  alias Tricep.Application
  alias Tricep.DataBuffer
  alias Tricep.Tcp

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

  @spec start_passive_connection(map()) :: :ignore | {:error, any()} | {:ok, pid()}
  def start_passive_connection(opts) do
    :gen_statem.start(__MODULE__, {:passive_connection, opts}, hibernate_after: 15_000)
  end

  use TypedStruct

  @ipv6_min_mtu 1280
  @tcp_ipv6_header_size 60
  # Default MSS for IPv6 (1280 min MTU - 40 IPv6 header - 20 TCP header)
  @default_mss @ipv6_min_mtu - @tcp_ipv6_header_size
  @default_recv_buffer_size 65_535
  @max_tcp_window 65_535
  @max_window_scale 14
  @max_scaled_tcp_window @max_tcp_window <<< @max_window_scale
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
    # Window scale we advertise to peer for our receive window
    field :rcv_wnd_scale, non_neg_integer(), default: 0
    # Window scale peer advertised for its receive window
    field :snd_wnd_scale, non_neg_integer(), default: 0
    # Buffers for data transfer
    field :send_buffer, DataBuffer.t(), default: DataBuffer.new()
    field :recv_buffer, binary(), default: <<>>
    field :out_of_order_segments, list(), default: []
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
    # Listening socket that owns this connection while the passive handshake completes
    field :passive_listener, pid() | nil, default: nil
  end

  # TIME_WAIT duration (2*MSL - using short value for TUN-based stack)
  @time_wait_ms 2_000

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init({:passive_connection, opts}) do
    state = passive_connection_state(opts)

    case Application.register_socket_pair(state.pair) do
      :ok ->
        {:ok, :syn_received, state}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  def init(opts) do
    {:ok, :closed, %{socket_opts: socket_opts(opts)}}
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
    cond do
      not listen_addr_matches?(listen_data.local_addr, dst_addr) ->
        :keep_state_and_data

      listen_backlog_full?(listen_data) ->
        :keep_state_and_data

      true ->
        case passive_link(src_addr, dst_addr) do
          {:ok, link, mtu} ->
            opts = %{
              listener: self(),
              src_addr: src_addr,
              dst_addr: dst_addr,
              src_port: src_port,
              dst_port: dst_port,
              segment: segment,
              link: link,
              mtu: mtu,
              socket_opts: listen_data.socket_opts
            }

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

          :error ->
            :keep_state_and_data
        end
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
        case Application.lookup_link(dstaddr_bin) do
          {pid, {srcaddr_bin, mtu}} ->
            case allocate_port(srcaddr_bin, {dstaddr_bin, dst_port}) do
              {:ok, pair} ->
                send_syn = {:next_event, :internal, {:send_syn, from, timeout}}
                recv_buffer_size = recv_buffer_size(closed_data)

                state = %__MODULE__{
                  pair: pair,
                  link: pid,
                  rcv_mss: mtu - 60,
                  recv_buffer_size: recv_buffer_size,
                  rcv_wnd: recv_buffer_size,
                  rcv_wnd_scale: window_scale_for(recv_buffer_size),
                  fin_wait_2_timeout_ms: fin_wait_2_timeout_ms(closed_data)
                }

                {:next_state, :closed, state, send_syn}

              {:error, reason} ->
                {:keep_state_and_data, {:reply, from, {:error, reason}}}
            end

          nil ->
            {:keep_state_and_data, {:reply, from, {:error, :enetunreach}}}
        end

      {:error, reason} ->
        {:keep_state_and_data, {:reply, from, {:error, reason}}}
    end
  end

  def handle_event({:call, from}, {:connect, address, timeout}, :bound, bound_data) do
    case validate_sockaddr_in6(address) do
      {:ok, dstaddr_bin, dst_port} ->
        case Application.lookup_link(dstaddr_bin) do
          {pid, {srcaddr_bin, mtu}} ->
            with {:ok, local_addr} <- bound_connect_source(bound_data.local_addr, srcaddr_bin),
                 :ok <-
                   Application.register_socket_pair(
                     {{local_addr, bound_data.local_port}, {dstaddr_bin, dst_port}}
                   ) do
              pair = {{local_addr, bound_data.local_port}, {dstaddr_bin, dst_port}}
              send_syn = {:next_event, :internal, {:send_syn, from, timeout}}
              recv_buffer_size = recv_buffer_size(bound_data)

              state = %__MODULE__{
                pair: pair,
                link: pid,
                rcv_mss: mtu - 60,
                recv_buffer_size: recv_buffer_size,
                rcv_wnd: recv_buffer_size,
                rcv_wnd_scale: window_scale_for(recv_buffer_size),
                fin_wait_2_timeout_ms: fin_wait_2_timeout_ms(bound_data)
              }

              deregister_bound_data(bound_data)
              {:next_state, :closed, state, send_syn}
            else
              {:error, :eaddrnotavail} ->
                {:keep_state_and_data, {:reply, from, {:error, :eaddrnotavail}}}

              {:error, {:already_registered, _pid}} ->
                {:keep_state_and_data, {:reply, from, {:error, :eaddrinuse}}}
            end

          nil ->
            {:keep_state_and_data, {:reply, from, {:error, :enetunreach}}}
        end

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
    rcv_wnd = advertised_receive_window(state)

    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(state.pair, iss, 0, [:syn], rcv_wnd,
        mss: state.rcv_mss,
        window_scale: state.rcv_wnd_scale
      )

    packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
    :ok = Tricep.Link.send(state.link, packet)

    base_state = %{
      state
      | iss: iss,
        snd_una: iss,
        snd_nxt: wrap_seq(iss + 1),
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
        expected_ack = state.snd_nxt

        cond do
          rst? ->
            reset_state(state)

            actions = [
              {{:timeout, :rto}, :cancel},
              {{:timeout, :connect_timeout}, :cancel},
              {:reply, from, {:error, :econnrefused}}
            ]

            {:next_state, :closed, nil, actions}

          syn? and ack? and ack == expected_ack ->
            # Valid SYN-ACK: send ACK and transition to ESTABLISHED
            send_ack(wrap_seq(seq + 1), state)

            # Extract peer's MSS from options, default to 1220 (IPv6 min MTU 1280 - 60) if not present
            snd_mss = Map.get(options, :mss, @default_mss)
            snd_wnd_scale = peer_window_scale(options)

            new_state = %{
              state
              | irs: seq,
                rcv_nxt: wrap_seq(seq + 1),
                snd_una: ack,
                snd_wnd: scale_window(window, snd_wnd_scale),
                snd_mss: snd_mss,
                snd_wnd_scale: snd_wnd_scale,
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

          ack? and ack != expected_ack ->
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
        expected_ack = state.snd_nxt

        cond do
          rst? ->
            # Connection refused - notify caller so a retry can complete with the stored error.
            actions = [{{:timeout, :rto}, :cancel}]
            {state_name, state_data} = nowait_connect_failure(state, :econnrefused)
            {:next_state, state_name, state_data, actions}

          syn? and ack? and ack == expected_ack ->
            # Valid SYN-ACK: send ACK, notify caller, transition to ESTABLISHED
            send_ack(wrap_seq(seq + 1), state)

            snd_mss = Map.get(options, :mss, @default_mss)
            snd_wnd_scale = peer_window_scale(options)

            # Notify callers that connect can complete
            notify_selects(state.connect_selects)

            new_state = %{
              state
              | irs: seq,
                rcv_nxt: wrap_seq(seq + 1),
                snd_una: ack,
                snd_wnd: scale_window(window, snd_wnd_scale),
                snd_mss: snd_mss,
                snd_wnd_scale: snd_wnd_scale,
                syn_retransmit_count: 0,
                rto_ms: @initial_rto_ms
            }

            actions = [{{:timeout, :rto}, :cancel}]
            {:next_state, :established, new_state, actions}

          ack? and ack != expected_ack ->
            send_rst(ack, state)
            :keep_state_and_data

          true ->
            :keep_state_and_data
        end

      _ ->
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
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: seq, ack: ack, window: window, payload: payload} ->
        syn? = :syn in flags
        ack? = :ack in flags
        rst? = :rst in flags

        cond do
          rst? and acceptable_rst?(state, seq) ->
            reset_state(state)
            notify_passive_listener(state, :passive_failed)
            {:next_state, :closed, nil, {{:timeout, :rto}, :cancel}}

          rst? ->
            reject_unacceptable_rst(state)

          ack? and ack == state.snd_nxt and seq == state.rcv_nxt ->
            base_state = %{
              state
              | snd_una: ack,
                snd_wnd: scale_peer_window(state, window),
                syn_retransmit_count: 0,
                rto_ms: @initial_rto_ms,
                passive_listener: nil
            }

            new_state =
              if byte_size(payload) > 0 do
                {receive_state, _accepted_len} = receive_payload(base_state, payload)
                send_ack(receive_state.rcv_nxt, receive_state)
                receive_state
              else
                base_state
              end

            notify_passive_listener(state, :passive_established)

            {:next_state, :established, new_state, {{:timeout, :rto}, :cancel}}

          ack? ->
            send_rst(ack, state)
            :keep_state_and_data

          syn? and seq == state.irs ->
            send_syn_ack(state)
            :keep_state_and_data

          true ->
            :keep_state_and_data
        end

      _ ->
        :keep_state_and_data
    end
  end

  def handle_event({:timeout, :rto}, :syn_ack_timeout, :syn_received, %__MODULE__{} = state) do
    if state.syn_retransmit_count >= @max_retransmit_count do
      reset_state(state)
      notify_passive_listener(state, :passive_failed)
      {:next_state, :closed, nil}
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
      %{flags: flags, seq: seq, ack: ack, payload: payload, window: window} = parsed ->
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

          not segment_acceptable?(state, parsed) ->
            reject_unacceptable_segment(state)

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
                |> Map.put(:snd_wnd, scale_peer_window(state, window))

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
                  {%{receive_state | snd_wnd: scale_peer_window(receive_state, window)}, []}
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

          byte_size(payload) > 0 ->
            receive_state = buffer_out_of_order_payload(state, seq, payload)
            {new_state, timer_actions} = process_ack_if_present(receive_state, ack?, ack, window)
            send_ack(new_state.rcv_nxt, new_state)
            {:keep_state, new_state, timer_actions}

          fin? ->
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
      %{flags: flags, seq: seq, ack: ack, window: window} = parsed ->
        fin? = :fin in flags
        ack? = :ack in flags
        rst? = :rst in flags
        ack_of_fin? = ack? and ack == state.snd_nxt

        cond do
          rst? and acceptable_rst?(state, seq) ->
            reset_state(state)
            {:next_state, :closed, nil, {{:timeout, :rto}, :cancel}}

          rst? ->
            reject_unacceptable_rst(state)

          not segment_acceptable?(state, parsed) ->
            reject_unacceptable_segment(state)

          true ->
            {ack_state, ack_actions} = process_ack_if_present(state, ack?, ack, window)

            cond do
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
                     {{:timeout, :fin_wait_2}, ack_state.fin_wait_2_timeout_ms,
                      :fin_wait_2_expired}
                   ]}

              ack? ->
                {:keep_state, ack_state, ack_actions}

              true ->
                :keep_state_and_data
            end
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
      %{flags: flags, seq: seq, ack: ack, payload: payload, window: window} = parsed ->
        fin? = :fin in flags
        ack? = :ack in flags
        rst? = :rst in flags

        cond do
          rst? and acceptable_rst?(state, seq) ->
            reset_state(state)
            {:next_state, :closed, nil, {{:timeout, :fin_wait_2}, :cancel}}

          rst? ->
            reject_unacceptable_rst(state)

          not segment_acceptable?(state, parsed) ->
            reject_unacceptable_segment(state)

          invalid_ack?(state, ack?, ack) ->
            reject_invalid_ack(state)

          fin? and seq == state.rcv_nxt ->
            # FIN from peer - ACK it and go to TIME_WAIT
            # Handle any data that came with the FIN
            data_len = byte_size(payload)

            {receive_state, accepted_len} =
              receive_payload(%{state | snd_wnd: scale_peer_window(state, window)}, payload)

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
            {new_state, _accepted_len} =
              receive_payload(%{state | snd_wnd: scale_peer_window(state, window)}, payload)

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
      %{flags: flags, seq: seq, ack: ack, window: window} = parsed ->
        ack? = :ack in flags
        rst? = :rst in flags
        ack_of_fin? = ack? and ack == state.snd_nxt

        cond do
          rst? and acceptable_rst?(state, seq) ->
            reset_state(state)
            {:next_state, :closed, nil, {{:timeout, :rto}, :cancel}}

          rst? ->
            reject_unacceptable_rst(state)

          not segment_acceptable?(state, parsed) ->
            reject_unacceptable_segment(state)

          true ->
            {ack_state, ack_actions} = process_ack_if_present(state, ack?, ack, window)

            cond do
              ack_of_fin? ->
                # ACK of our FIN - go to TIME_WAIT
                {:next_state, :time_wait, ack_state,
                 ack_actions ++ [{{:timeout, :time_wait}, @time_wait_ms, :time_wait_expired}]}

              ack? ->
                {:keep_state, ack_state, ack_actions}

              true ->
                :keep_state_and_data
            end
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
      %{flags: flags, seq: seq, ack: ack, window: window} = parsed ->
        rst? = :rst in flags
        ack? = :ack in flags

        cond do
          rst? and acceptable_rst?(state, seq) ->
            reset_state(state)
            actions = notify_waiters_error(state, :econnreset)
            {:next_state, :closed, nil, actions}

          rst? ->
            reject_unacceptable_rst(state)

          not segment_acceptable?(state, parsed) ->
            reject_unacceptable_segment(state)

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
      %{flags: flags, seq: seq, ack: ack, window: window} = parsed ->
        rst? = :rst in flags
        ack? = :ack in flags
        ack_of_fin? = ack? and ack == state.snd_nxt

        cond do
          rst? and acceptable_rst?(state, seq) ->
            reset_state(state)
            {:next_state, :closed, nil, {{:timeout, :rto}, :cancel}}

          rst? ->
            reject_unacceptable_rst(state)

          not segment_acceptable?(state, parsed) ->
            reject_unacceptable_segment(state)

          true ->
            {ack_state, ack_actions} = process_ack_if_present(state, ack?, ack, window)

            cond do
              ack_of_fin? ->
                # ACK of our FIN - connection fully closed
                reset_state(ack_state)
                {:next_state, :closed, nil, ack_actions}

              ack? ->
                {:keep_state, ack_state, ack_actions}

              true ->
                :keep_state_and_data
            end
        end

      _ ->
        :keep_state_and_data
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
      {0, wrap_seq(seq + segment_sequence_length(parsed)), [:rst, :ack]}
    end
  end

  defp segment_sequence_length(%{flags: flags, payload: payload}) do
    byte_size(payload) + flag_sequence_length(flags, :syn) + flag_sequence_length(flags, :fin)
  end

  defp flag_sequence_length(flags, flag), do: if(flag in flags, do: 1, else: 0)

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
    rcv_wnd_scale = window_scale_for(recv_buffer_size)
    snd_wnd_scale = peer_window_scale(options)

    %__MODULE__{
      pair: {{dst_addr, dst_port}, {src_addr, src_port}},
      link: link,
      iss: iss,
      snd_una: iss,
      snd_nxt: wrap_seq(iss + 1),
      snd_wnd: scale_window(window, snd_wnd_scale),
      irs: seq,
      rcv_nxt: wrap_seq(seq + 1),
      rcv_wnd: recv_buffer_size,
      rcv_mss: mtu - 60,
      snd_mss: Map.get(options, :mss, @default_mss),
      rcv_wnd_scale: rcv_wnd_scale,
      snd_wnd_scale: snd_wnd_scale,
      recv_buffer_size: recv_buffer_size,
      rto_ms: @initial_rto_ms,
      syn_retransmit_count: 0,
      fin_wait_2_timeout_ms: configured_fin_wait_2_timeout_ms(socket_opts),
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

  defp put_child(listen_data, child, ref, status) do
    %{listen_data | children: Map.put(listen_data.children, child, {ref, status})}
  end

  defp remove_listen_child(listen_data, child) do
    case Map.pop(listen_data.children, child) do
      {{_ref, :pending}, children} ->
        %{
          listen_data
          | children: children,
            pending_count: max(0, listen_data.pending_count - 1)
        }

      {{_ref, :queued}, children} ->
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

    tcp_segment =
      Tcp.build_segment(
        state.pair,
        state.iss,
        state.rcv_nxt,
        [:syn, :ack],
        advertised_receive_window(state),
        mss: state.rcv_mss,
        window_scale: state.rcv_wnd_scale
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

  defp notify_passive_listener(%__MODULE__{passive_listener: listener}, message)
       when is_pid(listener) do
    send(listener, {message, self()})
  end

  defp notify_passive_listener(%__MODULE__{}, _message), do: :ok

  defp retransmit_syn(state, timeout_event) do
    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(state.pair, state.iss, 0, [:syn], advertised_receive_window(state),
        mss: state.rcv_mss,
        window_scale: state.rcv_wnd_scale
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
          advertised_receive_window(state),
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

  defp settle_close_waiters(%__MODULE__{} = state) do
    notify_selects(state.recv_selects)

    {recv_buffer, _recv_waiters, recv_actions} =
      process_waiters_eof(state.recv_buffer, state.recv_waiters)

    send_actions = notify_send_waiters_error(state.send_waiters, :epipe)

    new_state = %{
      state
      | recv_buffer: recv_buffer,
        recv_waiters: [],
        recv_selects: [],
        send_waiters: []
    }

    {new_state, recv_actions ++ send_actions}
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
            advertised_receive_window(state),
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
      Tcp.build_segment(
        state.pair,
        state.snd_nxt,
        ack_num,
        [:ack],
        advertised_receive_window(state)
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
        state.rcv_nxt,
        [:fin, :ack],
        advertised_receive_window(state)
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
    min(size, @max_scaled_tcp_window)
  end

  defp normalize_recv_buffer_size(_size), do: @default_recv_buffer_size

  defp normalize_fin_wait_2_timeout_ms(timeout_ms)
       when is_integer(timeout_ms) and timeout_ms > 0 do
    timeout_ms
  end

  defp normalize_fin_wait_2_timeout_ms(_timeout_ms), do: @default_fin_wait_2_timeout_ms

  defp receive_window(%__MODULE__{} = state) do
    buffered_bytes = byte_size(state.recv_buffer) + out_of_order_size(state)
    max(0, state.recv_buffer_size - buffered_bytes)
  end

  defp advertised_receive_window(%__MODULE__{} = state) do
    state
    |> receive_window()
    |> then(&(&1 >>> state.rcv_wnd_scale))
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
      |> drain_out_of_order_segments()
      |> refresh_receive_window()

    {new_state, accepted_len}
  end

  defp out_of_order_size(%__MODULE__{out_of_order_segments: segments}) do
    Enum.reduce(segments, 0, fn {_seq, _seq_end, payload}, total ->
      total + byte_size(payload)
    end)
  end

  defp buffer_out_of_order_payload(%__MODULE__{} = state, seq, payload)
       when byte_size(payload) > 0 do
    cond do
      not seq_gt(seq, state.rcv_nxt) ->
        state

      true ->
        offset = sequence_distance(state.rcv_nxt, seq)
        accepted_len = min(byte_size(payload), max(0, receive_window(state) - offset))

        if accepted_len > 0 do
          {accepted_payload, _overflow} = split_binary(payload, accepted_len)
          seq_end = wrap_seq(seq + accepted_len)

          segments =
            [{seq, seq_end, accepted_payload} | state.out_of_order_segments]
            |> sort_out_of_order_segments(state.rcv_nxt)
            |> merge_out_of_order_segments()

          %{state | out_of_order_segments: segments}
          |> refresh_receive_window()
        else
          state
        end
    end
  end

  defp buffer_out_of_order_payload(%__MODULE__{} = state, _seq, _payload), do: state

  defp sort_out_of_order_segments(segments, rcv_nxt) do
    Enum.sort_by(segments, fn {seq, _seq_end, _payload} ->
      sequence_distance(rcv_nxt, seq)
    end)
  end

  defp merge_out_of_order_segments([]), do: []

  defp merge_out_of_order_segments([segment | rest]) do
    rest
    |> Enum.reduce([segment], &merge_out_of_order_segment/2)
    |> Enum.reverse()
  end

  defp merge_out_of_order_segment({seq, seq_end, payload}, [
         {current_seq, current_end, current_payload} | rest
       ]) do
    cond do
      seq_gt(seq, current_end) ->
        [{seq, seq_end, payload}, {current_seq, current_end, current_payload} | rest]

      seq_gt(seq_end, current_end) ->
        overlap = sequence_distance(seq, current_end)
        tail_len = byte_size(payload) - overlap
        tail = binary_part(payload, overlap, tail_len)
        [{current_seq, seq_end, current_payload <> tail} | rest]

      true ->
        [{current_seq, current_end, current_payload} | rest]
    end
  end

  defp drain_out_of_order_segments(%__MODULE__{} = state) do
    {drained_state, remaining} =
      Enum.reduce(state.out_of_order_segments, {state, []}, fn
        {seq, seq_end, payload}, {%__MODULE__{rcv_nxt: rcv_nxt} = acc_state, remaining} ->
          if seq == rcv_nxt do
            {%{
               acc_state
               | recv_buffer: acc_state.recv_buffer <> payload,
                 rcv_nxt: seq_end
             }, remaining}
          else
            {acc_state, [{seq, seq_end, payload} | remaining]}
          end
      end)

    %{drained_state | out_of_order_segments: Enum.reverse(remaining)}
  end

  defp sequence_distance(from, to), do: wrap_seq(to - from)

  defp window_scale_for(size) when is_integer(size) and size > @max_tcp_window do
    Enum.find(1..@max_window_scale, @max_window_scale, fn scale ->
      size <= @max_tcp_window <<< scale
    end)
  end

  defp window_scale_for(_size), do: 0

  defp peer_window_scale(options) do
    options
    |> Map.get(:window_scale, 0)
    |> normalize_window_scale()
  end

  defp normalize_window_scale(scale) when is_integer(scale) and scale >= 0 do
    min(scale, @max_window_scale)
  end

  defp normalize_window_scale(_scale), do: 0

  defp scale_peer_window(%__MODULE__{} = state, window) do
    scale_window(window, state.snd_wnd_scale)
  end

  defp scale_window(window, scale) when is_integer(window) and is_integer(scale) do
    window <<< scale
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
            advertised_receive_window(state),
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
    current_mss = state.snd_mss || @default_mss

    if new_mss < current_mss do
      new_state = %{
        state
        | snd_mss: new_mss,
          unacked_segments: resegment_unacked_segments(state.unacked_segments, new_mss)
      }

      actions = schedule_flush_send_buffer(new_state, [])
      {new_state, actions}
    else
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
    [{seq, wrap_seq(seq + byte_size(payload)), payload, count}]
  end

  defp resegment_payload(seq, payload, count, mss) do
    {chunk, rest} = split_binary(payload, mss)
    next_seq = wrap_seq(seq + byte_size(chunk))

    [{seq, next_seq, chunk, count} | resegment_payload(next_seq, rest, count, mss)]
  end

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
    |> Map.put(:snd_wnd, scale_peer_window(state, window))
    |> sync_persist_timer([])
  end

  defp process_ack_if_present(state, true, ack, window), do: process_ack(state, ack, window)

  defp invalid_ack?(state, true, ack), do: seq_gt(ack, state.snd_nxt)
  defp invalid_ack?(_state, false, _ack), do: false

  defp segment_acceptable?(state, %{seq: seq} = segment) do
    window = receive_window(state)
    segment_len = segment_sequence_length(segment)

    cond do
      window == 0 and segment_len == 0 ->
        seq == state.rcv_nxt

      window == 0 ->
        false

      segment_len == 0 ->
        seq_in_receive_window?(seq, state.rcv_nxt, window)

      true ->
        last_seq = wrap_seq(seq + segment_len - 1)

        seq_in_receive_window?(seq, state.rcv_nxt, window) or
          seq_in_receive_window?(last_seq, state.rcv_nxt, window)
    end
  end

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

  defp reject_unacceptable_segment(state) do
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
            snd_wnd: scale_peer_window(state, window),
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
        base_state = %{state | snd_wnd: scale_peer_window(state, window)}
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
