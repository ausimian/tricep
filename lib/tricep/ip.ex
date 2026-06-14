defmodule Tricep.Ip do
  @moduledoc false

  @tcp 6
  @udp 17
  @icmpv6 58
  @max_payload_length 65_535
  @max_next_header 255

  @type parsed_packet :: %{
          version: 6,
          traffic_class: non_neg_integer(),
          flow_label: non_neg_integer(),
          payload_length: non_neg_integer(),
          next_header: non_neg_integer(),
          hop_limit: non_neg_integer(),
          src: binary(),
          dst: binary(),
          payload: binary()
        }

  @spec wrap(binary(), binary(), atom() | integer(), binary()) :: binary()
  def wrap(src_addr, dst_addr, protocol, payload)
      when byte_size(src_addr) == 16 and byte_size(dst_addr) == 16 do
    version = 6
    traffic_class = 0
    flow_label = 0
    payload_length = payload |> byte_size() |> validate_payload_length()
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

  defp protocol_number(n) when is_integer(n) and n in 0..@max_next_header, do: n

  defp protocol_number(n) when is_integer(n) do
    raise ArgumentError, "IPv6 next header must be in 0..#{@max_next_header}, got #{n}"
  end

  defp validate_payload_length(length) when length <= @max_payload_length, do: length

  defp validate_payload_length(length) do
    raise ArgumentError,
          "IPv6 payload length #{length} exceeds #{@max_payload_length}; jumbograms are not supported"
  end

  @spec parse(binary()) :: {:ok, parsed_packet()} | {:error, atom()}
  def parse(
        <<6::4, traffic_class::8, flow_label::20, payload_length::16, next_header::8,
          hop_limit::8, src::binary-size(16), dst::binary-size(16), payload::binary>>
      )
      when byte_size(payload) == payload_length do
    {:ok,
     %{
       version: 6,
       traffic_class: traffic_class,
       flow_label: flow_label,
       payload_length: payload_length,
       next_header: next_header,
       hop_limit: hop_limit,
       src: src,
       dst: dst,
       payload: payload
     }}
  end

  def parse(
        <<6::4, _traffic_class::8, _flow_label::20, payload_length::16, _next_header::8,
          _hop_limit::8, _src::binary-size(16), _dst::binary-size(16), payload::binary>>
      )
      when byte_size(payload) != payload_length do
    {:error, :invalid_payload_length}
  end

  def parse(<<version::4, _::bits>>) when version != 6, do: {:error, :unsupported_version}
  def parse(_packet), do: {:error, :truncated_header}
end
