defmodule Tricep.TcpTest do
  use ExUnit.Case, async: true

  alias Tricep.Tcp

  @src_addr <<0xFE, 0x80, 0::104, 0x01>>
  @dst_addr <<0xFE, 0x80, 0::104, 0x02>>

  describe "encode_flags/1" do
    test "encodes single SYN flag" do
      assert Tcp.encode_flags([:syn]) == 0x02
    end

    test "encodes single ACK flag" do
      assert Tcp.encode_flags([:ack]) == 0x10
    end

    test "encodes SYN+ACK flags" do
      result = Tcp.encode_flags([:syn, :ack])
      assert result == 0x12
    end

    test "encodes all flags" do
      flags = [:fin, :syn, :rst, :psh, :ack, :urg, :ece, :cwr]
      result = Tcp.encode_flags(flags)
      assert result == 0xFF
    end

    test "encodes empty flags" do
      assert Tcp.encode_flags([]) == 0
    end

    test "encodes RST flag" do
      assert Tcp.encode_flags([:rst]) == 0x04
    end

    test "encodes FIN+ACK flags" do
      result = Tcp.encode_flags([:fin, :ack])
      assert result == 0x11
    end
  end

  describe "decode_flags/1" do
    test "decodes SYN flag" do
      assert :syn in Tcp.decode_flags(0x02)
    end

    test "decodes ACK flag" do
      assert :ack in Tcp.decode_flags(0x10)
    end

    test "decodes SYN+ACK flags" do
      flags = Tcp.decode_flags(0x12)
      assert :syn in flags
      assert :ack in flags
    end

    test "decodes zero as empty list" do
      assert Tcp.decode_flags(0) == []
    end

    test "decodes all common flags" do
      # FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32 = 0x3F
      flags = Tcp.decode_flags(0x3F)
      assert :fin in flags
      assert :syn in flags
      assert :rst in flags
      assert :psh in flags
      assert :ack in flags
      assert :urg in flags
    end
  end

  describe "encode_flags/1 and decode_flags/1 roundtrip" do
    test "roundtrip preserves flags" do
      original = [:syn, :ack]
      encoded = Tcp.encode_flags(original)
      decoded = Tcp.decode_flags(encoded)

      assert Enum.sort(original) == Enum.sort(decoded)
    end
  end

  describe "build_segment/1" do
    test "builds valid TCP segment with SYN flag" do
      segment =
        Tcp.build_segment(
          src_addr: @src_addr,
          dst_addr: @dst_addr,
          src_port: 12345,
          dst_port: 80,
          seq: 1000,
          ack: 0,
          flags: [:syn],
          window: 65535
        )

      # Minimum TCP header is 20 bytes (no options, data_offset=5)
      assert byte_size(segment) == 20

      <<
        src_port::16,
        dst_port::16,
        seq::32,
        ack::32,
        data_offset::4,
        _reserved::4,
        flags::8,
        window::16,
        _checksum::16,
        urgent_ptr::16
      >> = segment

      assert src_port == 12345
      assert dst_port == 80
      assert seq == 1000
      assert ack == 0
      assert data_offset == 5
      assert flags == 0x02
      assert window == 65535
      assert urgent_ptr == 0
    end

    test "builds segment with payload" do
      payload = <<"Hello, World!">>

      segment =
        Tcp.build_segment(
          src_addr: @src_addr,
          dst_addr: @dst_addr,
          src_port: 12345,
          dst_port: 80,
          seq: 1000,
          ack: 2000,
          flags: [:ack, :psh],
          window: 32768,
          payload: payload
        )

      assert byte_size(segment) == 20 + byte_size(payload)

      <<_header::binary-size(20), data::binary>> = segment
      assert data == payload
    end

    test "calculates non-zero checksum" do
      segment =
        Tcp.build_segment(
          src_addr: @src_addr,
          dst_addr: @dst_addr,
          src_port: 12345,
          dst_port: 80,
          seq: 1000,
          ack: 0,
          flags: [:syn],
          window: 65535
        )

      <<_::binary-size(16), checksum::16, _::binary>> = segment
      assert checksum != 0
    end
  end

  describe "parse_segment/1" do
    test "parses valid SYN segment" do
      segment =
        Tcp.build_segment(
          src_addr: @src_addr,
          dst_addr: @dst_addr,
          src_port: 12345,
          dst_port: 80,
          seq: 1000,
          ack: 0,
          flags: [:syn],
          window: 65535
        )

      parsed = Tcp.parse_segment(segment)

      assert parsed.seq == 1000
      assert parsed.ack == 0
      assert :syn in parsed.flags
      assert parsed.window == 65535
      assert parsed.payload == <<>>
    end

    test "parses segment with payload" do
      payload = <<"Test data">>

      segment =
        Tcp.build_segment(
          src_addr: @src_addr,
          dst_addr: @dst_addr,
          src_port: 12345,
          dst_port: 80,
          seq: 1000,
          ack: 2000,
          flags: [:ack],
          window: 32768,
          payload: payload
        )

      parsed = Tcp.parse_segment(segment)

      assert parsed.payload == payload
    end

    test "returns nil for truncated segment" do
      assert Tcp.parse_segment(<<1, 2, 3>>) == nil
    end

    test "returns nil for empty binary" do
      assert Tcp.parse_segment(<<>>) == nil
    end
  end

  describe "checksum/3" do
    test "calculates checksum for segment" do
      segment = <<
        0x30,
        0x39,
        0x00,
        0x50,
        0x00,
        0x00,
        0x03,
        0xE8,
        0x00,
        0x00,
        0x00,
        0x00,
        0x50,
        0x02,
        0xFF,
        0xFF,
        0x00,
        0x00,
        0x00,
        0x00
      >>

      checksum = Tcp.checksum(@src_addr, @dst_addr, segment)

      # Checksum should be non-zero
      assert checksum != 0
      assert checksum <= 0xFFFF
    end

    test "checksum validates correctly" do
      # Build a segment, then verify the checksum is valid
      segment =
        Tcp.build_segment(
          src_addr: @src_addr,
          dst_addr: @dst_addr,
          src_port: 12345,
          dst_port: 80,
          seq: 1000,
          ack: 0,
          flags: [:syn],
          window: 65535
        )

      # Extract the checksum
      <<_::binary-size(16), original_checksum::16, _::binary>> = segment

      # Zero out checksum in segment
      <<prefix::binary-size(16), _::16, suffix::binary>> = segment
      segment_zero_checksum = prefix <> <<0::16>> <> suffix

      # Recalculate
      recalculated = Tcp.checksum(@src_addr, @dst_addr, segment_zero_checksum)

      assert recalculated == original_checksum
    end
  end

  describe "build_segment/1 and parse_segment/1 roundtrip" do
    test "roundtrip preserves segment data" do
      segment =
        Tcp.build_segment(
          src_addr: @src_addr,
          dst_addr: @dst_addr,
          src_port: 54321,
          dst_port: 443,
          seq: 0xDEADBEEF,
          ack: 0xCAFEBABE,
          flags: [:syn, :ack],
          window: 16384,
          payload: <<"roundtrip test">>
        )

      parsed = Tcp.parse_segment(segment)

      assert parsed.seq == 0xDEADBEEF
      assert parsed.ack == 0xCAFEBABE
      assert :syn in parsed.flags
      assert :ack in parsed.flags
      assert parsed.window == 16384
      assert parsed.payload == <<"roundtrip test">>
    end
  end
end
