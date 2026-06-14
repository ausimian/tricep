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

  def from({a, b, c, d, e, f, g, h})
      when a in 0..0xFFFF and b in 0..0xFFFF and c in 0..0xFFFF and d in 0..0xFFFF and
             e in 0..0xFFFF and f in 0..0xFFFF and g in 0..0xFFFF and h in 0..0xFFFF do
    {:ok, <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>}
  end

  def from({_a, _b, _c, _d, _e, _f, _g, _h}), do: {:error, :einval}
end
