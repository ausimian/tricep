defmodule Tricep.TcpSocket do
  @behaviour :gen_statem

  alias Tricep.Application
  import Bitwise
  require Logger

  @spec connect(pid(), :socket.sockaddr_in6()) :: :ok | {:error, any()}
  def connect(pid, address) when is_pid(pid) do
    :gen_statem.call(pid, {:connect, address})
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

    {{src_addr, src_port}, {dst_addr, dst_port}} = state.pair

    tcp_segment =
      build_segment(
        src_addr: src_addr,
        dst_addr: dst_addr,
        src_port: src_port,
        dst_port: dst_port,
        seq: iss,
        ack: 0,
        flags: [:syn],
        window: rcv_wnd,
        payload: <<>>
      )

    packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
    :ok = Tricep.Link.send(state.link, packet)

    new_state = %{state | iss: iss, snd_una: iss, snd_nxt: iss + 1, snd_wnd: 0, rcv_wnd: rcv_wnd}

    {:next_state, {:syn_sent, from}, new_state}
  end

  def handle_event(:info, segment, {:syn_sent, from}, %__MODULE__{} = state) do
    case parse_segment(segment) do
      %{flags: flags, seq: seq, ack: ack, window: window} ->
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

            new_state = %{state | irs: seq, rcv_nxt: seq + 1, snd_una: ack, snd_wnd: window}

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

  defp reset_state(%__MODULE__{} = state) do
    Application.deregister_socket_pair(state.pair)
  end

  defp parse_segment(<<
         _src_port::16,
         _dst_port::16,
         seq::32,
         ack::32,
         data_offset::4,
         _reserved::4,
         flags::8,
         window::16,
         _checksum::16,
         _urgent::16,
         rest::binary
       >>) do
    header_bytes = data_offset * 4
    options_len = header_bytes - 20
    <<_options::binary-size(options_len), payload::binary>> = rest

    %{
      seq: seq,
      ack: ack,
      flags: decode_flags(flags),
      window: window,
      payload: payload
    }
  end

  defp parse_segment(_), do: nil

  defp decode_flags(bits) do
    flags = []
    flags = if (bits &&& 0x01) != 0, do: [:fin | flags], else: flags
    flags = if (bits &&& 0x02) != 0, do: [:syn | flags], else: flags
    flags = if (bits &&& 0x04) != 0, do: [:rst | flags], else: flags
    flags = if (bits &&& 0x08) != 0, do: [:psh | flags], else: flags
    flags = if (bits &&& 0x10) != 0, do: [:ack | flags], else: flags
    flags = if (bits &&& 0x20) != 0, do: [:urg | flags], else: flags
    flags
  end

  defp send_ack(ack_num, %__MODULE__{} = state) do
    {{src_addr, src_port}, {dst_addr, dst_port}} = state.pair

    tcp_segment =
      build_segment(
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
      build_segment(
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

  defp build_segment(opts) do
    src_addr = Keyword.fetch!(opts, :src_addr)
    dst_addr = Keyword.fetch!(opts, :dst_addr)
    src_port = Keyword.fetch!(opts, :src_port)
    dst_port = Keyword.fetch!(opts, :dst_port)
    seq = Keyword.fetch!(opts, :seq)
    ack = Keyword.fetch!(opts, :ack)
    flags = Keyword.fetch!(opts, :flags)
    window = Keyword.fetch!(opts, :window)
    payload = Keyword.get(opts, :payload, <<>>)

    data_offset = 5
    reserved = 0
    urgent_ptr = 0
    flag_bits = encode_flags(flags)

    # Build segment with zero checksum first
    segment_no_checksum = <<
      src_port::16,
      dst_port::16,
      seq::32,
      ack::32,
      data_offset::4,
      reserved::4,
      flag_bits::8,
      window::16,
      0::16,
      urgent_ptr::16,
      payload::binary
    >>

    checksum = tcp_checksum(src_addr, dst_addr, segment_no_checksum)

    <<
      src_port::16,
      dst_port::16,
      seq::32,
      ack::32,
      data_offset::4,
      reserved::4,
      flag_bits::8,
      window::16,
      checksum::16,
      urgent_ptr::16,
      payload::binary
    >>
  end

  defp tcp_checksum(src_addr, dst_addr, segment) do
    tcp_len = byte_size(segment)

    pseudo_header = <<
      src_addr::binary-size(16),
      dst_addr::binary-size(16),
      tcp_len::32,
      0::24,
      6::8
    >>

    data = pseudo_header <> segment
    data = if rem(byte_size(data), 2) == 1, do: data <> <<0>>, else: data

    sum = checksum_fold(data, 0)
    bnot(sum) &&& 0xFFFF
  end

  defp checksum_fold(<<word::16, rest::binary>>, acc) do
    sum = acc + word
    carry = sum >>> 16
    checksum_fold(rest, (sum &&& 0xFFFF) + carry)
  end

  defp checksum_fold(<<>>, acc), do: acc

  defp encode_flags(flags) do
    Enum.reduce(flags, 0, fn
      :fin, acc -> acc ||| 0x01
      :syn, acc -> acc ||| 0x02
      :rst, acc -> acc ||| 0x04
      :psh, acc -> acc ||| 0x08
      :ack, acc -> acc ||| 0x10
      :urg, acc -> acc ||| 0x20
      :ece, acc -> acc ||| 0x40
      :cwr, acc -> acc ||| 0x80
    end)
  end
end
