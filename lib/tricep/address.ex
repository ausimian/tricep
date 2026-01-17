defmodule Tricep.Address do
  @moduledoc false

  def to_bytes({a, b, c, d, e, f, g, h}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
  end

  def from(addr_str) when is_binary(addr_str) do
    with {:ok, addr_tuple} <- :inet.parse_ipv6strict_address(to_charlist(addr_str)) do
      from(addr_tuple)
    end
  end

  def from({a, b, c, d, e, f, g, h}) do
    {:ok, <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>}
  end
end
