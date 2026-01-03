defmodule Tricep.Nifs do
  @on_load :load_nif

  @doc """
  Get the MTU of a network interface.

  ## Examples

      iex> Tricep.Nifs.get_mtu("lo")
      {:ok, 65536}

      iex> Tricep.Nifs.get_mtu("nonexistent")
      {:error, :ioctl_failed}
  """
  @spec get_mtu(String.t()) :: {:ok, non_neg_integer()} | {:error, atom()}
  def get_mtu(_ifname) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc """
  Compute one's complement checksum over iodata.

  Uses graph reduction to walk the iodata structure without flattening,
  computing the checksum as 16-bit words in network byte order.

  ## Examples

      iex> Tricep.Nifs.checksum(<<0, 0>>)
      65535

      iex> Tricep.Nifs.checksum([<<1, 2>>, <<3, 4>>])
      64250
  """
  @spec checksum(iodata()) :: non_neg_integer()
  def checksum(_iodata) do
    :erlang.nif_error(:nif_not_loaded)
  end

  defp load_nif do
    path = :filename.join(:code.priv_dir(:tricep), ~c"tricep_nif")
    :erlang.load_nif(path, 0)
  end
end
