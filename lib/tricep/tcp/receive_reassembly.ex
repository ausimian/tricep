defmodule Tricep.Tcp.ReceiveReassembly do
  @moduledoc false

  # TCP permits a segment to straddle either edge of the receive window. This
  # module keeps the receive-side reconstruction rules separate from Socket's
  # OTP buffering and state transitions: it clips a segment to the current
  # window, retains detached non-overlapping chunks, and drains contiguous
  # bytes.

  alias Tricep.Tcp.Sequence

  # A fixed bound keeps reassembly work predictable even when a peer fills the
  # receive window with alternating single-byte segments. The count applies to
  # physical chunks, including adjacent chunks, so iodata cannot hide an
  # unbounded number of retained packet slices. Socket additionally supplies a
  # byte budget which reserves front-recovery capacity outside this queue.
  # After draining, retain the lowest sequence-space chunks and evict the
  # highest tail. TCP will elicit retransmission of an evicted tail after its
  # preceding gap drains.
  @max_fragment_count 128

  @type sequence :: Sequence.sequence_number()
  @type queued_segment :: {sequence(), sequence(), binary()}
  # An out-of-order FIN is only a hint while the payload that carried it stays
  # queued. The payload start is provenance: data which merely happens to end
  # at the FIN marker must not manufacture EOF.
  @type pending_fin :: {sequence(), sequence()} | nil

  @type result :: %{
          delivered: binary(),
          evicted_count: non_neg_integer(),
          fin?: boolean(),
          fin_sequence: sequence() | nil,
          pending_fin: pending_fin(),
          out_of_order_segments: [queued_segment()],
          rcv_nxt: sequence()
        }

  @doc false
  @spec max_fragment_count() :: pos_integer()
  def max_fragment_count, do: @max_fragment_count

  @spec receive([queued_segment()], pending_fin(), sequence(), non_neg_integer(), map()) ::
          result()
  def receive(segments, pending_fin, rcv_nxt, receive_window, segment) do
    receive(segments, pending_fin, rcv_nxt, receive_window, nil, segment)
  end

  @spec receive(
          [queued_segment()],
          pending_fin(),
          sequence(),
          non_neg_integer(),
          non_neg_integer() | nil,
          map()
        ) :: result()
  def receive(segments, pending_fin, rcv_nxt, receive_window, out_of_order_byte_budget, %{
        flags: flags,
        payload: payload,
        seq: sequence
      }) do
    # The socket only feeds this module the queue returned by its previous
    # call. That queue is ordered, disjoint, and capped; keep it that way so
    # every receive operation has a fixed upper bound on its list traversal.
    segments = segments |> Enum.take(@max_fragment_count) |> trim_delivered(rcv_nxt)

    {segments, accepted_payload, new_sequences} =
      insert_payload(segments, rcv_nxt, receive_window, sequence, payload)

    pending_fin = revoke_conflicting_fin(segments, pending_fin, rcv_nxt)

    {segments, pending_fin} =
      insert_fin(
        segments,
        pending_fin,
        rcv_nxt,
        receive_window,
        sequence,
        payload,
        flags,
        accepted_payload
      )

    result = drain(segments, pending_fin, rcv_nxt)

    result
    |> enforce_reassembly_limits(
      remaining_byte_budget(out_of_order_byte_budget, result.delivered)
    )
    |> detach_new_chunks(new_sequences)
  end

  defp trim_delivered(segments, rcv_nxt) do
    Enum.flat_map(segments, fn {sequence, _sequence_end, payload} ->
      trim_left(sequence, payload, rcv_nxt)
    end)
  end

  defp trim_left(sequence, payload, rcv_nxt) do
    cond do
      sequence == rcv_nxt ->
        [{sequence, Sequence.wrap(sequence + byte_size(payload)), payload}]

      Sequence.gt?(sequence, rcv_nxt) ->
        [{sequence, Sequence.wrap(sequence + byte_size(payload)), payload}]

      true ->
        sequence_end = Sequence.wrap(sequence + byte_size(payload))

        if Sequence.gt?(sequence_end, rcv_nxt) do
          overlap = Sequence.distance(sequence, rcv_nxt)
          length = byte_size(payload) - overlap
          trimmed = binary_part(payload, overlap, length)
          [{rcv_nxt, sequence_end, :binary.copy(trimmed)}]
        else
          []
        end
    end
  end

  defp insert_payload(segments, _rcv_nxt, _receive_window, _sequence, <<>>),
    do: {segments, nil, MapSet.new()}

  defp insert_payload(segments, rcv_nxt, receive_window, sequence, payload) do
    case clip_payload(rcv_nxt, receive_window, sequence, payload) do
      nil ->
        {segments, nil, MapSet.new()}

      {offset, clipped_payload} ->
        fragments = subtract_queued(segments, rcv_nxt, offset, clipped_payload)
        reassembled = insert_fragments(segments, fragments, rcv_nxt)
        clipped_sequence = Sequence.wrap(rcv_nxt + offset)

        new_sequences =
          MapSet.new(fragments, fn {fragment_offset, _payload} ->
            Sequence.wrap(rcv_nxt + fragment_offset)
          end)

        {reassembled,
         {clipped_sequence, Sequence.wrap(clipped_sequence + byte_size(clipped_payload))},
         new_sequences}
    end
  end

  defp clip_payload(rcv_nxt, receive_window, sequence, payload) do
    start_offset = signed_offset(sequence, rcv_nxt)
    end_offset = start_offset + byte_size(payload)
    clipped_start = max(start_offset, 0)
    clipped_end = min(end_offset, receive_window)

    if clipped_start < clipped_end do
      start_in_payload = clipped_start - start_offset
      clipped_length = clipped_end - clipped_start

      clipped_payload =
        if start_in_payload == 0 and clipped_length == byte_size(payload) do
          payload
        else
          binary_part(payload, start_in_payload, clipped_length)
        end

      {clipped_start, clipped_payload}
    end
  end

  # Both the queued ranges and the fragments produced here are ordered. Walk
  # them once rather than repeatedly subtracting every queued range from every
  # growing fragment list.
  defp subtract_queued(segments, rcv_nxt, offset, payload) do
    subtract_queued(segments, rcv_nxt, offset, offset + byte_size(payload), offset, payload, [])
  end

  defp subtract_queued([], _rcv_nxt, cursor, ending, offset, payload, fragments) do
    fragments
    |> maybe_add_fragment(cursor, ending, offset, payload)
    |> Enum.reverse()
  end

  defp subtract_queued(
         [{sequence, _sequence_end, queued_payload} | rest],
         rcv_nxt,
         cursor,
         ending,
         offset,
         payload,
         fragments
       ) do
    queued_start = signed_offset(sequence, rcv_nxt)
    queued_end = queued_start + byte_size(queued_payload)

    cond do
      ending <= queued_start ->
        fragments
        |> maybe_add_fragment(cursor, ending, offset, payload)
        |> Enum.reverse()

      queued_end <= cursor ->
        subtract_queued(rest, rcv_nxt, cursor, ending, offset, payload, fragments)

      true ->
        fragment_end = min(queued_start, ending)
        fragments = maybe_add_fragment(fragments, cursor, fragment_end, offset, payload)
        cursor = max(cursor, queued_end)

        if cursor >= ending do
          Enum.reverse(fragments)
        else
          subtract_queued(rest, rcv_nxt, cursor, ending, offset, payload, fragments)
        end
    end
  end

  defp maybe_add_fragment(fragments, start, ending, offset, payload) do
    if start < ending do
      length = ending - start
      payload_offset = start - offset

      fragment =
        if payload_offset == 0 and length == byte_size(payload) do
          payload
        else
          binary_part(payload, payload_offset, length)
        end

      [{start, fragment} | fragments]
    else
      fragments
    end
  end

  defp insert_fragments(segments, [], _rcv_nxt), do: segments

  defp insert_fragments(segments, fragments, rcv_nxt) do
    incoming =
      Enum.map(fragments, fn {offset, payload} ->
        sequence = Sequence.wrap(rcv_nxt + offset)
        {sequence, Sequence.wrap(sequence + byte_size(payload)), payload}
      end)

    # Keep adjacent chunks separate. Extending a retained run with
    # `current_payload <> tail` would copy the full run on every later packet;
    # chunks are materialized once when drain_payload/4 reaches RCV.NXT.
    interleave(segments, incoming, rcv_nxt)
  end

  defp interleave([], right, _rcv_nxt), do: right
  defp interleave(left, [], _rcv_nxt), do: left

  defp interleave(
         [{left_sequence, _left_end, _left_payload} = left | left_rest],
         [{right_sequence, _right_end, _right_payload} = right | right_rest],
         rcv_nxt
       ) do
    if signed_offset(left_sequence, rcv_nxt) <= signed_offset(right_sequence, rcv_nxt) do
      [left | interleave(left_rest, [right | right_rest], rcv_nxt)]
    else
      [right | interleave([left | left_rest], right_rest, rcv_nxt)]
    end
  end

  # A bare out-of-order FIN is advisory but uncorroborated, so it is discarded
  # until retransmitted in order. An out-of-order FIN carried by accepted data
  # is retained only while no accepted payload extends beyond its marker.
  defp insert_fin(
         segments,
         pending_fin,
         rcv_nxt,
         receive_window,
         sequence,
         payload,
         flags,
         accepted_payload
       ) do
    if :fin in flags do
      fin_sequence = Sequence.wrap(sequence + byte_size(payload))
      fin_offset = signed_offset(fin_sequence, rcv_nxt)

      cond do
        not accepted_fin?(fin_offset, receive_window) ->
          {segments, pending_fin}

        fin_offset == 0 ->
          # A current FIN supersedes every stale out-of-order hint.
          {segments, {fin_sequence, fin_sequence}}

        accepted_payload == nil ->
          # A peer must retransmit a bare FIN when it reaches RCV.NXT.
          {segments, pending_fin}

        payload_end(accepted_payload) != fin_sequence ->
          {segments, pending_fin}

        payload_extends_past_fin?(segments, fin_offset, rcv_nxt) ->
          {segments, pending_fin}

        true ->
          # A valid current FIN replaces a stale hint when the queued data is
          # consistent with its boundary.
          {segments, {fin_sequence, payload_start(accepted_payload)}}
      end
    else
      {segments, pending_fin}
    end
  end

  defp payload_extends_past_fin?(segments, offset, rcv_nxt) do
    Enum.any?(segments, fn {sequence, _sequence_end, payload} ->
      start_offset = signed_offset(sequence, rcv_nxt)
      offset < start_offset + byte_size(payload)
    end)
  end

  defp revoke_conflicting_fin(_segments, nil, _rcv_nxt), do: nil

  defp revoke_conflicting_fin(segments, {fin_sequence, _payload_start} = pending_fin, rcv_nxt) do
    fin_offset = signed_offset(fin_sequence, rcv_nxt)

    case payload_extends_past_fin?(segments, fin_offset, rcv_nxt) do
      true -> nil
      false -> pending_fin
    end
  end

  # A segment admitted at the left edge may carry a FIN exactly at the right
  # receive-window edge. The payload fills the window and the FIN then commits
  # immediately, avoiding a zero-window EOF deadlock.
  defp accepted_fin?(offset, receive_window), do: offset >= 0 and offset <= receive_window

  defp drain(segments, pending_fin, rcv_nxt) do
    {delivered, segments, rcv_nxt, drained} = drain_payload(segments, rcv_nxt, [], [])

    if fin_committable?(pending_fin, rcv_nxt, drained) do
      %{
        delivered: IO.iodata_to_binary(Enum.reverse(delivered)),
        evicted_count: 0,
        fin?: true,
        fin_sequence: nil,
        pending_fin: nil,
        out_of_order_segments: [],
        rcv_nxt: Sequence.wrap(rcv_nxt + 1)
      }
    else
      %{
        delivered: IO.iodata_to_binary(Enum.reverse(delivered)),
        evicted_count: 0,
        fin?: false,
        fin_sequence: fin_sequence(pending_fin),
        pending_fin: pending_fin,
        out_of_order_segments: segments,
        rcv_nxt: rcv_nxt
      }
    end
  end

  # Retain a lowest-sequence prefix under both physical-chunk and byte limits.
  # Socket reserves up to one local MSS outside the byte budget, so an
  # RCV.NXT retransmission still fits the advertised window. We deliberately
  # evict only the high tail rather than shrink that window at fragment
  # pressure, because front progress is what restores reassembly capacity.
  defp enforce_reassembly_limits(
         %{out_of_order_segments: segments, rcv_nxt: rcv_nxt} = result,
         byte_budget
       ) do
    {retained, evicted} = retain_reassembly_prefix(segments, byte_budget)

    if evicted == [] do
      result
    else
      pending_fin = retain_pending_fin(result.pending_fin, retained, rcv_nxt)

      %{
        result
        | out_of_order_segments: retained,
          evicted_count: length(evicted),
          pending_fin: pending_fin,
          fin_sequence: fin_sequence(pending_fin)
      }
    end
  end

  defp remaining_byte_budget(nil, _delivered), do: :infinity

  defp remaining_byte_budget(byte_budget, delivered) do
    max(0, byte_budget - byte_size(delivered))
  end

  defp retain_reassembly_prefix(segments, :infinity) do
    Enum.split(segments, @max_fragment_count)
  end

  defp retain_reassembly_prefix(segments, byte_budget) do
    retain_reassembly_prefix(segments, byte_budget, 0, 0, [])
  end

  defp retain_reassembly_prefix([], _byte_budget, _count, _retained_bytes, retained) do
    {Enum.reverse(retained), []}
  end

  defp retain_reassembly_prefix(
         [{_sequence, _sequence_end, payload} = segment | rest],
         byte_budget,
         count,
         retained_bytes,
         retained
       ) do
    segment_bytes = byte_size(payload)

    if count < @max_fragment_count and retained_bytes + segment_bytes <= byte_budget do
      retain_reassembly_prefix(
        rest,
        byte_budget,
        count + 1,
        retained_bytes + segment_bytes,
        [segment | retained]
      )
    else
      {Enum.reverse(retained), [segment | rest]}
    end
  end

  # Detach only packet slices inserted by this call that survived both the
  # RCV.NXT drain and tail eviction. In-order input is materialized directly
  # by drain/3, and previously retained chunks are never recopied merely
  # because an Erlang allocator reports a larger backing block.
  defp detach_new_chunks(%{out_of_order_segments: segments} = result, new_sequences) do
    %{result | out_of_order_segments: Enum.map(segments, &detach_new_chunk(&1, new_sequences))}
  end

  defp detach_new_chunk({sequence, sequence_end, payload} = segment, new_sequences) do
    if MapSet.member?(new_sequences, sequence) do
      {sequence, sequence_end, :binary.copy(payload)}
    else
      segment
    end
  end

  defp retain_pending_fin(nil, _segments, _rcv_nxt), do: nil

  defp retain_pending_fin({fin_sequence, payload_start} = pending_fin, segments, rcv_nxt) do
    fin_offset = signed_offset(fin_sequence, rcv_nxt)
    payload_start_offset = signed_offset(payload_start, rcv_nxt)

    if retained_fin_payload?(segments, rcv_nxt, payload_start_offset, fin_offset) do
      pending_fin
    end
  end

  defp retained_fin_payload?(_segments, _rcv_nxt, cursor, ending) when cursor >= ending, do: true

  defp retained_fin_payload?([], _rcv_nxt, _cursor, _ending), do: false

  defp retained_fin_payload?(
         [{sequence, _sequence_end, payload} | rest],
         rcv_nxt,
         cursor,
         ending
       ) do
    start_offset = signed_offset(sequence, rcv_nxt)
    end_offset = start_offset + byte_size(payload)

    cond do
      end_offset <= cursor ->
        retained_fin_payload?(rest, rcv_nxt, cursor, ending)

      start_offset > cursor ->
        false

      true ->
        retained_fin_payload?(rest, rcv_nxt, max(cursor, end_offset), ending)
    end
  end

  # Admission/revocation plus the ordered-chunk invariant enforce the FIN boundary.
  # This is defense in depth: commit only if the original FIN-carrying range
  # itself drained contiguously, not merely because unrelated data ends there.
  defp fin_committable?({fin_sequence, payload_start}, fin_sequence, drained) do
    payload_start == fin_sequence or
      Enum.any?(drained, fn {start, ending} ->
        Sequence.lte?(start, payload_start) and Sequence.gt?(ending, payload_start)
      end)
  end

  defp fin_committable?(_, _rcv_nxt, _drained), do: false

  defp drain_payload([{sequence, sequence_end, payload} | rest], sequence, delivered, drained) do
    drain_payload(rest, sequence_end, [payload | delivered], [{sequence, sequence_end} | drained])
  end

  defp drain_payload(segments, rcv_nxt, delivered, drained),
    do: {delivered, segments, rcv_nxt, drained}

  defp payload_start({start, _ending}), do: start
  defp payload_end({_start, ending}), do: ending
  defp fin_sequence(nil), do: nil
  defp fin_sequence({sequence, _payload_start}), do: sequence

  defp signed_offset(sequence, base) do
    cond do
      sequence == base -> 0
      Sequence.gt?(sequence, base) -> Sequence.distance(base, sequence)
      true -> -Sequence.distance(sequence, base)
    end
  end
end
