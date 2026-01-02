defmodule Tricep.IpTest do
  use ExUnit.Case, async: true

  alias Tricep.Ip

  @src_addr <<0xFE, 0x80, 0::104, 0x01>>
  @dst_addr <<0xFE, 0x80, 0::104, 0x02>>

  describe "wrap/4" do
    test "wraps TCP payload in IPv6 header" do
      payload = <<1, 2, 3, 4>>
      packet = Ip.wrap(@src_addr, @dst_addr, :tcp, payload)

      # IPv6 header is 40 bytes
      assert byte_size(packet) == 40 + byte_size(payload)

      <<
        version::4,
        traffic_class::8,
        flow_label::20,
        payload_length::16,
        next_header::8,
        hop_limit::8,
        src::binary-size(16),
        dst::binary-size(16),
        rest::binary
      >> = packet

      assert version == 6
      assert traffic_class == 0
      assert flow_label == 0
      assert payload_length == byte_size(payload)
      assert next_header == 6
      assert hop_limit == 64
      assert src == @src_addr
      assert dst == @dst_addr
      assert rest == payload
    end

    test "wraps UDP payload with correct protocol number" do
      payload = <<1, 2, 3, 4>>
      packet = Ip.wrap(@src_addr, @dst_addr, :udp, payload)

      <<_::binary-size(6), next_header::8, _::binary>> = packet
      assert next_header == 17
    end

    test "wraps ICMPv6 payload with correct protocol number" do
      payload = <<1, 2, 3, 4>>
      packet = Ip.wrap(@src_addr, @dst_addr, :icmpv6, payload)

      <<_::binary-size(6), next_header::8, _::binary>> = packet
      assert next_header == 58
    end

    test "accepts integer protocol number" do
      payload = <<1, 2, 3, 4>>
      packet = Ip.wrap(@src_addr, @dst_addr, 99, payload)

      <<_::binary-size(6), next_header::8, _::binary>> = packet
      assert next_header == 99
    end

    test "handles empty payload" do
      packet = Ip.wrap(@src_addr, @dst_addr, :tcp, <<>>)

      <<_::binary-size(4), payload_length::16, _::binary>> = packet
      assert payload_length == 0
      assert byte_size(packet) == 40
    end

    test "handles large payload" do
      payload = :binary.copy(<<0xFF>>, 1000)
      packet = Ip.wrap(@src_addr, @dst_addr, :tcp, payload)

      <<_::binary-size(4), payload_length::16, _::binary>> = packet
      assert payload_length == 1000
      assert byte_size(packet) == 40 + 1000
    end
  end
end
