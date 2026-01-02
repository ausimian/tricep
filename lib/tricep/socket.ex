defmodule Tricep.Socket do
  @behaviour :gen_statem

  import Bitwise

  alias Tricep.Application
  alias Tricep.Tcp
  require Logger

  @spec connect(pid(), :socket.sockaddr_in6()) :: :ok | {:error, any()}
  def connect(pid, address) when is_pid(pid) do
    :gen_statem.call(pid, {:connect, address})
  end

  @spec send_data(pid(), binary()) :: :ok | {:error, atom()}
  def send_data(pid, data) when is_pid(pid) and is_binary(data) do
    :gen_statem.call(pid, {:send, data})
  end

  @spec recv(pid(), non_neg_integer(), timeout()) :: {:ok, binary()} | {:error, atom()}
  def recv(pid, length \\ 0, timeout \\ :infinity) when is_pid(pid) do
    :gen_statem.call(pid, {:recv, length, timeout})
  end

  def handle_packet(src_addr, dst_addr, <<src_port::16, dst_port::16, _::binary>> = segment) do
    pair = {{dst_addr, dst_port}, {src_addr, src_port}}

    if pid = Application.lookup_socket_pair(pair) do
      send(pid, segment)
    end

    :ok
  end

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
    field :send_buffer, binary(), default: <<>>
    field :recv_buffer, binary(), default: <<>>
    # Callers waiting on recv (list of {from, length})
    field :recv_waiters, list(), default: []
  end

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init(_opts) do
    {:ok, :closed, nil}
  end

  @impl true
  def handle_event({:call, from}, {:connect, %{addr: addr} = address}, :closed, nil) do
    case Tricep.Address.from(addr) do
      {:ok, dstaddr_bin} ->
        case Application.lookup_link(dstaddr_bin) do
          {pid, srcaddr_bin} ->
            pair = allocate_port(srcaddr_bin, {dstaddr_bin, address.port})
            send_syn = {:next_event, :internal, {:send_syn, from}}
            {:next_state, :closed, %__MODULE__{pair: pair, link: pid}, send_syn}

          nil ->
            {:keep_state_and_data, {:reply, from, {:error, :enetunreach}}}
        end

      {:error, _} = err ->
        {:keep_state_and_data, {:reply, from, err}}
    end
  end

  def handle_event({:call, from}, {:connect, _address}, _, %__MODULE__{}) do
    {:keep_state_and_data, {:reply, from, {:error, :eisconn}}}
  end

  def handle_event(:internal, {:send_syn, from}, :closed, %__MODULE__{} = state) do
    iss = :crypto.strong_rand_bytes(4) |> :binary.decode_unsigned()
    rcv_wnd = 65535
    rcv_mss = @default_mss

    {{src_addr, src_port}, {dst_addr, dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(
        src_addr: src_addr,
        dst_addr: dst_addr,
        src_port: src_port,
        dst_port: dst_port,
        seq: iss,
        ack: 0,
        flags: [:syn],
        window: rcv_wnd,
        mss: rcv_mss
      )

    packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
    :ok = Tricep.Link.send(state.link, packet)

    new_state = %{
      state
      | iss: iss,
        snd_una: iss,
        snd_nxt: iss + 1,
        snd_wnd: 0,
        rcv_wnd: rcv_wnd,
        rcv_mss: rcv_mss
    }

    {:next_state, {:syn_sent, from}, new_state}
  end

  def handle_event(:info, segment, {:syn_sent, from}, %__MODULE__{} = state) do
    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: seq, ack: ack, window: window, options: options} ->
        syn? = :syn in flags
        ack? = :ack in flags
        rst? = :rst in flags

        cond do
          rst? ->
            reset_state(state)
            {:next_state, :closed, nil, {:reply, from, {:error, :econnrefused}}}

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
                snd_mss: snd_mss
            }

            {:next_state, :established, new_state, {:reply, from, :ok}}

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

  # --- Established state: send ---

  def handle_event({:call, from}, {:send, data}, :established, %__MODULE__{} = state) do
    new_state = %{state | send_buffer: state.send_buffer <> data}
    {:keep_state, new_state, [{:reply, from, :ok}, {:next_event, :internal, :flush_send_buffer}]}
  end

  def handle_event(:internal, :flush_send_buffer, :established, %__MODULE__{send_buffer: <<>>} = _state) do
    :keep_state_and_data
  end

  def handle_event(:internal, :flush_send_buffer, :established, %__MODULE__{} = state) do
    # Take up to snd_mss bytes from buffer
    mss = state.snd_mss || @default_mss
    {payload, rest} = split_binary(state.send_buffer, mss)

    {{src_addr, src_port}, {dst_addr, dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(
        src_addr: src_addr,
        dst_addr: dst_addr,
        src_port: src_port,
        dst_port: dst_port,
        seq: state.snd_nxt,
        ack: state.rcv_nxt,
        flags: [:ack, :psh],
        window: state.rcv_wnd,
        payload: payload
      )

    packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
    Tricep.Link.send(state.link, packet)

    new_state = %{
      state
      | send_buffer: rest,
        snd_nxt: wrap_seq(state.snd_nxt + byte_size(payload))
    }

    # If more data to send, schedule another flush
    actions = if rest != <<>>, do: [{:next_event, :internal, :flush_send_buffer}], else: []
    {:keep_state, new_state, actions}
  end

  # --- Established state: recv ---

  def handle_event({:call, from}, {:recv, length, timeout}, :established, %__MODULE__{} = state) do
    case deliver_data(state.recv_buffer, length) do
      {:ok, data, rest} ->
        new_state = %{state | recv_buffer: rest}
        {:keep_state, new_state, {:reply, from, {:ok, data}}}

      :wait ->
        # No data available, add to waiters with timeout
        timer_ref = make_ref()
        waiter = {from, length, timer_ref}
        new_state = %{state | recv_waiters: state.recv_waiters ++ [waiter]}

        actions =
          if timeout == :infinity do
            []
          else
            [{{:timeout, timer_ref}, timeout, {:recv_timeout, timer_ref}}]
          end

        {:keep_state, new_state, actions}
    end
  end

  # Handle recv timeout
  def handle_event({:timeout, timer_ref}, {:recv_timeout, timer_ref}, :established, %__MODULE__{} = state) do
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

          ack? and seq == state.rcv_nxt and byte_size(payload) > 0 ->
            # Data segment with expected sequence number
            new_rcv_nxt = wrap_seq(state.rcv_nxt + byte_size(payload))
            new_recv_buffer = state.recv_buffer <> payload
            new_snd_una = if ack > state.snd_una, do: ack, else: state.snd_una

            # Send ACK for received data
            send_ack(new_rcv_nxt, %{state | rcv_nxt: new_rcv_nxt})

            # Check if any waiters can be satisfied
            {new_recv_buffer, new_waiters, replies} =
              process_waiters(new_recv_buffer, state.recv_waiters)

            new_state = %{
              state
              | rcv_nxt: new_rcv_nxt,
                recv_buffer: new_recv_buffer,
                recv_waiters: new_waiters,
                snd_una: new_snd_una,
                snd_wnd: window
            }

            {:keep_state, new_state, replies}

          ack? and byte_size(payload) == 0 ->
            # Pure ACK - update send window
            new_snd_una = if ack > state.snd_una, do: ack, else: state.snd_una
            new_state = %{state | snd_una: new_snd_una, snd_wnd: window}
            {:keep_state, new_state}

          true ->
            # Out of order or unexpected - ignore for now
            :keep_state_and_data
        end

      _ ->
        :keep_state_and_data
    end
  end

  # Send/recv on non-established socket
  def handle_event({:call, from}, {:send, _data}, _state, _state_data) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  def handle_event({:call, from}, {:recv, _length, _timeout}, _state, _state_data) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  defp reset_state(%__MODULE__{} = state) do
    Application.deregister_socket_pair(state.pair)
  end

  defp send_ack(ack_num, %__MODULE__{} = state) do
    {{src_addr, src_port}, {dst_addr, dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(
        src_addr: src_addr,
        dst_addr: dst_addr,
        src_port: src_port,
        dst_port: dst_port,
        seq: state.snd_nxt,
        ack: ack_num,
        flags: [:ack],
        window: state.rcv_wnd,
        payload: <<>>
      )

    packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
    Tricep.Link.send(state.link, packet)
  end

  defp send_rst(seq_num, %__MODULE__{} = state) do
    {{src_addr, src_port}, {dst_addr, dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(
        src_addr: src_addr,
        dst_addr: dst_addr,
        src_port: src_port,
        dst_port: dst_port,
        seq: seq_num,
        ack: 0,
        flags: [:rst],
        window: 0,
        payload: <<>>
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
        Logger.debug("Port #{port} already in use, retrying")
        allocate_port(srcaddr_bin, dst, state)
    end
  end

  # --- Helper functions ---

  # Wrap sequence number at 32 bits
  defp wrap_seq(n), do: n &&& 0xFFFFFFFF

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
end
