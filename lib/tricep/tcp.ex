defmodule Tricep.Tcp do
  @moduledoc false

  import Bitwise

  @type flag :: :fin | :syn | :rst | :psh | :ack | :urg | :ece | :cwr

  @type tcp_options :: %{
          optional(:mss) => non_neg_integer(),
          optional(:window_scale) => non_neg_integer(),
          optional(:sack_permitted) => boolean(),
          optional(:sack_blocks) => [{non_neg_integer(), non_neg_integer()}],
          optional(:timestamp) => {non_neg_integer(), non_neg_integer()}
        }

  @type parsed_segment :: %{
          seq: non_neg_integer(),
          ack: non_neg_integer(),
          flags: [flag()],
          window: non_neg_integer(),
          payload: binary(),
          options: tcp_options()
        }

  @doc """
  Builds a TCP segment.

  ## Arguments

  - `pair` - tuple of `{{src_addr, src_port}, {dst_addr, dst_port}}`
  - `seq` - sequence number
  - `ack` - acknowledgment number
  - `flags` - list of flags (e.g., `[:syn, :ack]`)
  - `window` - window size
  - `opts` - optional keyword list:
    - `:payload` - data payload (default: `<<>>`)
    - `:mss` - Maximum Segment Size option (typically sent in SYN)
    - `:window_scale` - TCP Window Scale shift count
    - `:sack_permitted` - Emit SACK-permitted option when true
    - `:sack_blocks` - SACK block edges as `{left, right}` tuples
    - `:timestamp` - TCP timestamp `{tsval, tsecr}` tuple
  """
  @spec build_segment(
          {{binary(), non_neg_integer()}, {binary(), non_neg_integer()}},
          non_neg_integer(),
          non_neg_integer(),
          [flag()],
          non_neg_integer(),
          keyword()
        ) :: binary()
  def build_segment(pair, seq, ack, flags, window, opts \\ [])

  def build_segment({{src_addr, src_port}, {dst_addr, dst_port}}, seq, ack, flags, window, opts) do
    payload = Keyword.get(opts, :payload, <<>>)

    # Build TCP options
    options = encode_options(opts)
    options_len = byte_size(options)

    # data_offset is in 32-bit words (base header is 5 words = 20 bytes)
    data_offset = 5 + div(options_len, 4)
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
      options::binary,
      payload::binary
    >>

    checksum = checksum(src_addr, dst_addr, segment_no_checksum)

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
      options::binary,
      payload::binary
    >>
  end

  defp encode_options(opts) do
    base_options =
      [
        encode_mss_option(Keyword.get(opts, :mss)),
        encode_window_scale_option(Keyword.get(opts, :window_scale)),
        encode_sack_permitted_option(Keyword.get(opts, :sack_permitted, false)),
        encode_timestamp_option(Keyword.get(opts, :timestamp))
      ]
      |> IO.iodata_to_binary()

    sack_blocks =
      opts
      |> Keyword.get(:sack_blocks, [])
      |> encode_sack_blocks_option()
      |> IO.iodata_to_binary()

    [
      base_options,
      if(byte_size(base_options) + byte_size(sack_blocks) <= 40, do: sack_blocks, else: <<>>)
    ]
    |> IO.iodata_to_binary()
    |> pad_options()
  end

  defp encode_mss_option(nil), do: <<>>
  defp encode_mss_option(mss) when is_integer(mss) and mss in 0..65_535, do: <<2, 4, mss::16>>
  defp encode_mss_option(_mss), do: <<>>

  defp encode_window_scale_option(nil), do: <<>>

  defp encode_window_scale_option(scale) when is_integer(scale) and scale in 0..255 do
    <<3, 3, scale>>
  end

  defp encode_window_scale_option(_scale), do: <<>>

  defp encode_sack_permitted_option(true), do: <<4, 2>>
  defp encode_sack_permitted_option(_sack_permitted), do: <<>>

  defp encode_timestamp_option({tsval, tsecr})
       when is_integer(tsval) and tsval in 0..0xFFFFFFFF and is_integer(tsecr) and
              tsecr in 0..0xFFFFFFFF do
    <<8, 10, tsval::32, tsecr::32>>
  end

  defp encode_timestamp_option(_timestamp), do: <<>>

  defp encode_sack_blocks_option([]), do: <<>>

  defp encode_sack_blocks_option(blocks) when is_list(blocks) do
    blocks =
      blocks
      |> Enum.take(4)
      |> Enum.filter(fn
        {left, right}
        when is_integer(left) and left in 0..0xFFFFFFFF and is_integer(right) and
               right in 0..0xFFFFFFFF ->
          true

        _ ->
          false
      end)

    case blocks do
      [] ->
        <<>>

      blocks ->
        encoded_blocks =
          Enum.map(blocks, fn {left, right} ->
            <<left::32, right::32>>
          end)

        [<<5, 2 + length(blocks) * 8>>, encoded_blocks]
    end
  end

  defp encode_sack_blocks_option(_blocks), do: <<>>

  defp pad_options(options) do
    case rem(byte_size(options), 4) do
      0 -> options
      n -> options <> :binary.copy(<<0>>, 4 - n)
    end
  end

  @doc """
  Parses a TCP segment binary into a map.

  Returns `nil` if the segment is malformed.
  """
  @spec parse_segment(binary()) :: parsed_segment() | nil
  def parse_segment(<<
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

    case rest do
      <<options_bin::binary-size(options_len), payload::binary>> ->
        %{
          seq: seq,
          ack: ack,
          flags: decode_flags(flags),
          window: window,
          payload: payload,
          options: parse_options(options_bin)
        }

      _ ->
        nil
    end
  end

  def parse_segment(_), do: nil

  @doc """
  Parses TCP options from the options portion of a TCP header.
  """
  @spec parse_options(binary()) :: tcp_options()
  def parse_options(options_bin) do
    parse_options(options_bin, %{})
  end

  defp parse_options(<<>>, acc), do: acc

  # End of options (kind=0)
  defp parse_options(<<0, _rest::binary>>, acc), do: acc

  # NOP (kind=1)
  defp parse_options(<<1, rest::binary>>, acc), do: parse_options(rest, acc)

  # MSS (kind=2, length=4)
  defp parse_options(<<2, 4, mss::16, rest::binary>>, acc) do
    parse_options(rest, Map.put(acc, :mss, mss))
  end

  # Window Scale (kind=3, length=3)
  defp parse_options(<<3, 3, scale, rest::binary>>, acc) do
    parse_options(rest, Map.put(acc, :window_scale, scale))
  end

  # SACK permitted (kind=4, length=2)
  defp parse_options(<<4, 2, rest::binary>>, acc) do
    parse_options(rest, Map.put(acc, :sack_permitted, true))
  end

  # SACK blocks (kind=5, length=2+8n)
  defp parse_options(<<5, len, rest::binary>>, acc) when len >= 10 and rem(len - 2, 8) == 0 do
    blocks_len = len - 2

    case rest do
      <<blocks_bin::binary-size(blocks_len), remaining::binary>> ->
        parse_options(remaining, Map.put(acc, :sack_blocks, parse_sack_blocks(blocks_bin)))

      _ ->
        acc
    end
  end

  # Timestamp (kind=8, length=10)
  defp parse_options(<<8, 10, tsval::32, tsecr::32, rest::binary>>, acc) do
    parse_options(rest, Map.put(acc, :timestamp, {tsval, tsecr}))
  end

  # Unknown option with length - skip it
  defp parse_options(<<_kind, len, rest::binary>>, acc) when len >= 2 do
    skip_len = len - 2

    case rest do
      <<_::binary-size(skip_len), remaining::binary>> ->
        parse_options(remaining, acc)

      _ ->
        acc
    end
  end

  # Malformed - stop parsing
  defp parse_options(_, acc), do: acc

  defp parse_sack_blocks(blocks_bin) do
    for <<left::32, right::32 <- blocks_bin>>, do: {left, right}
  end

  @doc """
  Decodes TCP flag bits into a list of flag atoms.
  """
  @spec decode_flags(integer()) :: [flag()]
  def decode_flags(bits) do
    flags = []
    flags = if (bits &&& 0x01) != 0, do: [:fin | flags], else: flags
    flags = if (bits &&& 0x02) != 0, do: [:syn | flags], else: flags
    flags = if (bits &&& 0x04) != 0, do: [:rst | flags], else: flags
    flags = if (bits &&& 0x08) != 0, do: [:psh | flags], else: flags
    flags = if (bits &&& 0x10) != 0, do: [:ack | flags], else: flags
    flags = if (bits &&& 0x20) != 0, do: [:urg | flags], else: flags
    flags = if (bits &&& 0x40) != 0, do: [:ece | flags], else: flags
    flags = if (bits &&& 0x80) != 0, do: [:cwr | flags], else: flags
    flags
  end

  @doc """
  Encodes a list of flag atoms into TCP flag bits.
  """
  @spec encode_flags([flag()]) :: integer()
  def encode_flags(flags) do
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

  @doc """
  Calculates the TCP checksum for a segment.

  Uses the IPv6 pseudo-header as specified in RFC 2460.
  The segment can be iodata, avoiding binary concatenation.
  """
  @spec checksum(binary(), binary(), iodata()) :: non_neg_integer()
  def checksum(src_addr, dst_addr, segment)
      when byte_size(src_addr) == 16 and byte_size(dst_addr) == 16 do
    Tricep.Nifs.checksum([
      src_addr,
      dst_addr,
      <<IO.iodata_length(segment)::32, 0::24, 6::8>>,
      segment
    ])
  end

  @doc """
  Validates a TCP segment checksum using the IPv6 pseudo-header.
  """
  @spec valid_checksum?(binary(), binary(), binary()) :: boolean()
  def valid_checksum?(src_addr, dst_addr, segment)
      when byte_size(src_addr) == 16 and byte_size(dst_addr) == 16 and is_binary(segment) do
    valid_header?(segment) and checksum(src_addr, dst_addr, segment) == 0
  end

  def valid_checksum?(_src_addr, _dst_addr, _segment), do: false

  defp valid_header?(<<
         _src_port::16,
         _dst_port::16,
         _seq::32,
         _ack::32,
         data_offset::4,
         _reserved::4,
         _flags::8,
         _window::16,
         _checksum::16,
         _urgent::16,
         rest::binary
       >>) do
    header_bytes = data_offset * 4
    data_offset >= 5 and header_bytes <= byte_size(rest) + 20
  end

  defp valid_header?(_segment), do: false
end
