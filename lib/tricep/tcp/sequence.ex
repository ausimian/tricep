defmodule Tricep.Tcp.Sequence do
  @moduledoc false

  # Internal arithmetic for TCP's unsigned 32-bit sequence-number space. TCP
  # compares serial numbers modulo 2^32 rather than as ordinary integers.

  import Bitwise

  @modulus 1 <<< 32
  @half_space 1 <<< 31
  @mask @modulus - 1

  @type sequence_number :: 0..0xFFFFFFFF
  @type segment :: %{
          required(:flags) => [atom()],
          required(:payload) => binary(),
          required(:seq) => sequence_number()
        }

  @spec wrap(integer()) :: sequence_number()
  def wrap(number), do: number &&& @mask

  # Returns whether `left` is after `right` in TCP serial-number space.
  @spec gt?(sequence_number(), sequence_number()) :: boolean()
  def gt?(left, right) do
    difference = wrap(left - right)
    difference > 0 and difference < @half_space
  end

  @spec gte?(sequence_number(), sequence_number()) :: boolean()
  def gte?(left, right), do: left == right or gt?(left, right)

  @spec lt?(sequence_number(), sequence_number()) :: boolean()
  def lt?(left, right), do: gt?(right, left)

  @spec lte?(sequence_number(), sequence_number()) :: boolean()
  def lte?(left, right), do: not gt?(left, right)

  # Returns the unsigned distance from `from` to `to` modulo 2^32.
  @spec distance(sequence_number(), sequence_number()) :: sequence_number()
  def distance(from, to), do: wrap(to - from)

  # Returns the sequence-space length of a TCP segment.
  @spec segment_length(segment()) :: non_neg_integer()
  def segment_length(%{flags: flags, payload: payload}) do
    byte_size(payload) + control_length(flags, :syn) + control_length(flags, :fin)
  end

  # Returns whether a sequence number lies in the receive window.
  @spec in_window?(sequence_number(), sequence_number(), non_neg_integer()) :: boolean()
  def in_window?(sequence, receive_next, 0), do: sequence == receive_next

  def in_window?(sequence, receive_next, window) do
    window_end = wrap(receive_next + window)
    gte?(sequence, receive_next) and lt?(sequence, window_end)
  end

  # Returns whether a segment intersects the advertised receive window.
  @spec acceptable?(segment(), sequence_number(), non_neg_integer()) :: boolean()
  def acceptable?(%{seq: sequence} = segment, receive_next, window) do
    length = segment_length(segment)

    cond do
      window == 0 and zero_window_fin?(segment, receive_next) ->
        true

      window == 0 and length == 0 ->
        sequence == receive_next

      window == 0 ->
        false

      length == 0 ->
        in_window?(sequence, receive_next, window)

      true ->
        last_sequence = wrap(sequence + length - 1)

        in_window?(sequence, receive_next, window) or
          in_window?(last_sequence, receive_next, window)
    end
  end

  defp zero_window_fin?(%{flags: flags, payload: payload, seq: sequence}, receive_next) do
    sequence == receive_next and payload == <<>> and :ack in flags and :fin in flags and
      :syn not in flags
  end

  defp control_length(flags, flag), do: if(flag in flags, do: 1, else: 0)
end
