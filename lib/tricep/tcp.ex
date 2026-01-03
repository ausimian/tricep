defmodule Tricep.Tcp do
  @moduledoc """
  TCP segment building, parsing, and checksum calculation.
  """

  import Bitwise

  @type flag :: :fin | :syn | :rst | :psh | :ack | :urg | :ece | :cwr

  @type tcp_options :: %{
          optional(:mss) => non_neg_integer()
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
    mss = Keyword.get(opts, :mss)

    # Build TCP options
    options = encode_options(mss: mss)
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
    mss = Keyword.get(opts, :mss)

    options =
      if mss do
        # MSS option: Kind=2, Length=4, Value=MSS
        <<2, 4, mss::16>>
      else
        <<>>
      end

    # Pad to 32-bit boundary with NOP (kind=1) or END (kind=0)
    pad_options(options)
  end

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
  """
  @spec checksum(binary(), binary(), binary()) :: non_neg_integer()
  def checksum(src_addr, dst_addr, segment)
      when byte_size(src_addr) == 16 and byte_size(dst_addr) == 16 do
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
end
