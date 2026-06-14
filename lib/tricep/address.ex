defmodule Tricep.Address do
  @moduledoc false

  def to_bytes({a, b, c, d, e, f, g, h}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
  end

  def from(addr) when is_binary(addr) do
    case parse_ipv6_string(addr) do
      {:ok, addr_tuple} ->
        from(addr_tuple)

      {:error, :einval} when byte_size(addr) == 16 ->
        {:ok, addr}

      {:error, :einval} ->
        {:error, :einval}
    end
  end

  def from({a, b, c, d, e, f, g, h})
      when a in 0..0xFFFF and b in 0..0xFFFF and c in 0..0xFFFF and d in 0..0xFFFF and
             e in 0..0xFFFF and f in 0..0xFFFF and g in 0..0xFFFF and h in 0..0xFFFF do
    {:ok, <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>}
  end

  def from({_a, _b, _c, _d, _e, _f, _g, _h}), do: {:error, :einval}

  defp parse_ipv6_string(addr) do
    if String.valid?(addr) do
      case :inet.parse_ipv6strict_address(String.to_charlist(addr)) do
        {:ok, addr_tuple} -> {:ok, addr_tuple}
        {:error, _reason} -> {:error, :einval}
      end
    else
      {:error, :einval}
    end
  rescue
    ArgumentError -> {:error, :einval}
    UnicodeConversionError -> {:error, :einval}
  end
end
