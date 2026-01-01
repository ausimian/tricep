defmodule Tricep.Ip do
  @tcp 6
  @udp 17
  @icmpv6 58

  @spec wrap(binary(), binary(), atom() | integer(), binary()) :: binary()
  def wrap(src_addr, dst_addr, protocol, payload)
      when byte_size(src_addr) == 16 and byte_size(dst_addr) == 16 do
    version = 6
    traffic_class = 0
    flow_label = 0
    payload_length = byte_size(payload)
    next_header = protocol_number(protocol)
    hop_limit = 64

    <<
      version::4,
      traffic_class::8,
      flow_label::20,
      payload_length::16,
      next_header::8,
      hop_limit::8,
      src_addr::binary-size(16),
      dst_addr::binary-size(16),
      payload::binary
    >>
  end

  defp protocol_number(:tcp), do: @tcp
  defp protocol_number(:udp), do: @udp
  defp protocol_number(:icmpv6), do: @icmpv6
  defp protocol_number(n) when is_integer(n), do: n
end
