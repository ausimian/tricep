defmodule Tricep.Tcp.ReceiveReassembly do
  @moduledoc false

  # TCP permits a segment to straddle either edge of the receive window. This
  # module keeps the receive-side reconstruction rules separate from Socket's
  # OTP buffering and state transitions: it clips a segment to the current
  # window, retains only data not already queued, and drains contiguous bytes.

  alias Tricep.Tcp.Sequence

  @type sequence :: Sequence.sequence_number()
  @type queued_segment :: {sequence(), sequence(), binary()}
  # An out-of-order FIN is only a hint while the payload that carried it stays
  # queued. The payload start is provenance: data which merely happens to end
  # at the FIN marker must not manufacture EOF.
  @type pending_fin :: {sequence(), sequence()} | nil

  @type result :: %{
          delivered: binary(),
          fin?: boolean(),
          fin_sequence: sequence() | nil,
          pending_fin: pending_fin(),
          out_of_order_segments: [queued_segment()],
          rcv_nxt: sequence()
        }

  @spec receive([queued_segment()], pending_fin(), sequence(), non_neg_integer(), map()) ::
          result()
  def receive(segments, pending_fin, rcv_nxt, receive_window, %{
        flags: flags,
        payload: payload,
        seq: sequence
      }) do
    {segments, accepted_payload} =
      segments
      |> normalize(rcv_nxt)
      |> insert_payload(rcv_nxt, receive_window, sequence, payload)

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

    drain(segments, pending_fin, rcv_nxt)
  end

  defp normalize(segments, rcv_nxt) do
    segments
    |> Enum.flat_map(fn {sequence, _sequence_end, payload} ->
      trim_left(sequence, payload, rcv_nxt)
    end)
    |> sort(rcv_nxt)
    |> merge()
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
          [{rcv_nxt, sequence_end, trimmed}]
        else
          []
        end
    end
  end

  defp insert_payload(segments, _rcv_nxt, _receive_window, _sequence, <<>>),
    do: {segments, nil}

  defp insert_payload(segments, rcv_nxt, receive_window, sequence, payload) do
    case clip_payload(rcv_nxt, receive_window, sequence, payload) do
      nil ->
        {segments, nil}

      {offset, clipped_payload} ->
        fragments = subtract_queued([{offset, clipped_payload}], segments, rcv_nxt)

        reassembled =
          (segments ++
             Enum.map(fragments, fn {fragment_offset, fragment_payload} ->
               fragment_sequence = Sequence.wrap(rcv_nxt + fragment_offset)

               {
                 fragment_sequence,
                 Sequence.wrap(fragment_sequence + byte_size(fragment_payload)),
                 fragment_payload
               }
             end))
          |> sort(rcv_nxt)
          |> merge()

        clipped_sequence = Sequence.wrap(rcv_nxt + offset)

        {reassembled,
         {clipped_sequence, Sequence.wrap(clipped_sequence + byte_size(clipped_payload))}}
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
      {clipped_start, binary_part(payload, start_in_payload, clipped_length)}
    end
  end

  defp subtract_queued(fragments, segments, rcv_nxt) do
    Enum.reduce(segments, fragments, fn {sequence, _sequence_end, payload}, fragments ->
      queued_start = signed_offset(sequence, rcv_nxt)
      queued_end = queued_start + byte_size(payload)

      Enum.flat_map(fragments, &subtract_fragment(&1, queued_start, queued_end))
    end)
  end

  defp subtract_fragment({fragment_start, fragment_payload}, queued_start, queued_end) do
    fragment_end = fragment_start + byte_size(fragment_payload)

    if fragment_end <= queued_start or fragment_start >= queued_end do
      [{fragment_start, fragment_payload}]
    else
      left_fragment(fragment_start, fragment_payload, queued_start) ++
        right_fragment(fragment_start, fragment_end, fragment_payload, queued_end)
    end
  end

  defp left_fragment(fragment_start, fragment_payload, queued_start) do
    if fragment_start < queued_start do
      left_length = queued_start - fragment_start
      [{fragment_start, binary_part(fragment_payload, 0, left_length)}]
    else
      []
    end
  end

  defp right_fragment(fragment_start, fragment_end, fragment_payload, queued_end) do
    if fragment_end > queued_end do
      right_offset = max(queued_end - fragment_start, 0)
      right_length = fragment_end - queued_end
      [{queued_end, binary_part(fragment_payload, right_offset, right_length)}]
    else
      []
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
        fin?: true,
        fin_sequence: nil,
        pending_fin: nil,
        out_of_order_segments: [],
        rcv_nxt: Sequence.wrap(rcv_nxt + 1)
      }
    else
      %{
        delivered: IO.iodata_to_binary(Enum.reverse(delivered)),
        fin?: false,
        fin_sequence: fin_sequence(pending_fin),
        pending_fin: pending_fin,
        out_of_order_segments: segments,
        rcv_nxt: rcv_nxt
      }
    end
  end

  # Admission/revocation plus the merge invariant enforce the FIN boundary.
  # This is defense in depth: commit only if the original FIN-carrying range
  # itself drained contiguously, not merely because unrelated data ends there.
  defp fin_committable?({fin_sequence, payload_start}, fin_sequence, drained) do
    payload_start == fin_sequence or
      Enum.any?(drained, fn {start, ending} ->
        Sequence.lte?(start, payload_start) and Sequence.gte?(ending, fin_sequence)
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

  defp sort(segments, rcv_nxt) do
    Enum.sort_by(segments, fn {sequence, _sequence_end, _payload} ->
      signed_offset(sequence, rcv_nxt)
    end)
  end

  defp merge([]), do: []

  defp merge([segment | rest]) do
    rest
    |> Enum.reduce([segment], &merge_segment/2)
    |> Enum.reverse()
  end

  defp merge_segment({sequence, sequence_end, payload}, [
         {current_sequence, current_end, current_payload} | rest
       ]) do
    cond do
      Sequence.gt?(sequence, current_end) ->
        [
          {sequence, sequence_end, payload},
          {current_sequence, current_end, current_payload} | rest
        ]

      Sequence.gt?(sequence_end, current_end) ->
        overlap = Sequence.distance(sequence, current_end)
        tail_length = byte_size(payload) - overlap
        tail = binary_part(payload, overlap, tail_length)
        [{current_sequence, sequence_end, current_payload <> tail} | rest]

      true ->
        [{current_sequence, current_end, current_payload} | rest]
    end
  end

  defp signed_offset(sequence, base) do
    cond do
      sequence == base -> 0
      Sequence.gt?(sequence, base) -> Sequence.distance(base, sequence)
      true -> -Sequence.distance(sequence, base)
    end
  end
end
