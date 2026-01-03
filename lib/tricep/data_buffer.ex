defmodule Tricep.DataBuffer do
  @moduledoc """
  A queue-based data buffer for efficient append and take operations.

  Avoids binary copy overhead by storing chunks in a queue rather than
  concatenating them. Provides O(1) amortized append and O(k) take where
  k is the number of chunks consumed.
  """

  @opaque t :: %__MODULE__{
            queue: :queue.queue(binary()),
            size: non_neg_integer()
          }

  defstruct queue: :queue.new(), size: 0

  @doc """
  Creates a new empty data buffer.
  """
  @spec new() :: t()
  def new, do: %__MODULE__{}

  @doc """
  Appends data to the buffer.

  Ignores empty binaries to avoid queue pollution.
  O(1) amortized time complexity.
  """
  @spec append(t(), binary()) :: t()
  def append(%__MODULE__{} = buffer, <<>>), do: buffer

  def append(%__MODULE__{queue: queue, size: size}, data) when is_binary(data) do
    %__MODULE__{
      queue: :queue.in(data, queue),
      size: size + byte_size(data)
    }
  end

  @doc """
  Returns the total number of bytes in the buffer.
  O(1) time complexity.
  """
  @spec size(t()) :: non_neg_integer()
  def size(%__MODULE__{size: size}), do: size

  @doc """
  Returns true if the buffer is empty.
  O(1) time complexity.
  """
  @spec empty?(t()) :: boolean()
  def empty?(%__MODULE__{size: 0}), do: true
  def empty?(%__MODULE__{}), do: false

  @doc """
  Takes up to `n` bytes from the front of the buffer.

  Returns `{taken_iodata, remaining_buffer}`.

  - If buffer has >= n bytes, returns exactly n bytes as iodata
  - If buffer has < n bytes, returns all available bytes as iodata
  - If buffer is empty, returns `{[], buffer}`

  O(k) where k is the number of chunks consumed.
  """
  @spec take(t(), non_neg_integer()) :: {iodata(), t()}
  def take(%__MODULE__{size: 0} = buffer, _n), do: {[], buffer}
  def take(%__MODULE__{} = buffer, 0), do: {[], buffer}

  def take(%__MODULE__{} = buffer, n) when n > 0 do
    take_loop(buffer, n, [])
  end

  defp take_loop(%__MODULE__{size: 0} = buffer, _remaining, acc) do
    {Enum.reverse(acc), buffer}
  end

  defp take_loop(%__MODULE__{} = buffer, 0, acc) do
    {Enum.reverse(acc), buffer}
  end

  defp take_loop(%__MODULE__{queue: queue, size: size}, remaining, acc) do
    case :queue.out(queue) do
      {:empty, _} ->
        {Enum.reverse(acc), %__MODULE__{queue: queue, size: 0}}

      {{:value, chunk}, rest_queue} ->
        chunk_size = byte_size(chunk)

        cond do
          chunk_size <= remaining ->
            new_buffer = %__MODULE__{queue: rest_queue, size: size - chunk_size}
            take_loop(new_buffer, remaining - chunk_size, [chunk | acc])

          chunk_size > remaining ->
            <<taken::binary-size(remaining), leftover::binary>> = chunk
            new_queue = :queue.in_r(leftover, rest_queue)
            new_buffer = %__MODULE__{queue: new_queue, size: size - remaining}
            {Enum.reverse([taken | acc]), new_buffer}
        end
    end
  end
end
