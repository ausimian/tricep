defmodule Tricep.Tcp do
  @moduledoc """
  TCP segment building, parsing, and checksum calculation.
  """

  import Bitwise

  @type flag :: :fin | :syn | :rst | :psh | :ack | :urg | :ece | :cwr

  @type parsed_segment :: %{
          seq: non_neg_integer(),
          ack: non_neg_integer(),
          flags: [flag()],
          window: non_neg_integer(),
          payload: binary()
        }

  @doc """
  Builds a TCP segment with the given options.

  Required options:
  - `:src_addr` - source IPv6 address (16 bytes)
  - `:dst_addr` - destination IPv6 address (16 bytes)
  - `:src_port` - source port
  - `:dst_port` - destination port
  - `:seq` - sequence number
  - `:ack` - acknowledgment number
  - `:flags` - list of flags (e.g., `[:syn, :ack]`)
  - `:window` - window size

  Optional:
  - `:payload` - data payload (default: `<<>>`)
  """
  @spec build_segment(keyword()) :: binary()
  def build_segment(opts) do
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
      payload::binary
    >>
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
      <<_options::binary-size(options_len), payload::binary>> ->
        %{
          seq: seq,
          ack: ack,
          flags: decode_flags(flags),
          window: window,
          payload: payload
        }

      _ ->
        nil
    end
  end

  def parse_segment(_), do: nil

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
