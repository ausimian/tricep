defmodule Tricep.Tcp.ReceiveReassembly do
  @moduledoc false

  # TCP permits a segment to straddle either edge of the receive window. This
  # module keeps the receive-side reconstruction rules separate from Socket's
  # OTP buffering and state transitions: it clips a segment to the current
  # window, retains only data not already queued, and drains contiguous bytes.

  alias Tricep.Tcp.Sequence

  @type sequence :: Sequence.sequence_number()
  @type queued_segment :: {sequence(), sequence(), binary()}

  @type result :: %{
          delivered: binary(),
          fin?: boolean(),
          fin_sequence: sequence() | nil,
          out_of_order_segments: [queued_segment()],
          rcv_nxt: sequence()
        }

  @spec receive([queued_segment()], sequence() | nil, sequence(), non_neg_integer(), map()) ::
          result()
  def receive(segments, pending_fin, rcv_nxt, receive_window, %{
        flags: flags,
        payload: payload,
        seq: sequence
      }) do
    segments =
      segments
      |> normalize(rcv_nxt)
      |> insert_payload(rcv_nxt, receive_window, sequence, payload)

    pending_fin = revoke_conflicting_fin(segments, pending_fin, rcv_nxt)

    {segments, pending_fin} =
      insert_fin(segments, pending_fin, rcv_nxt, receive_window, sequence, payload, flags)

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
    do: segments

  defp insert_payload(segments, rcv_nxt, receive_window, sequence, payload) do
    case clip_payload(rcv_nxt, receive_window, sequence, payload) do
      nil ->
        segments

      {offset, clipped_payload} ->
        fragments = subtract_queued([{offset, clipped_payload}], segments, rcv_nxt)

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

  # RFC 9293 §3.10.7.4 reconstructs overlaps so only new sequence space is
  # processed. A queued FIN is therefore provisional until RCV.NXT reaches
  # its marker: later accepted data at that marker revokes the FIN. Data after
  # an uncontradicted marker remains queued until commit, when it is purged.
  defp insert_fin(segments, pending_fin, rcv_nxt, receive_window, sequence, payload, flags) do
    if :fin in flags do
      fin_sequence = Sequence.wrap(sequence + byte_size(payload))
      fin_offset = signed_offset(fin_sequence, rcv_nxt)

      cond do
        not accepted_fin?(fin_offset, receive_window) ->
          {segments, pending_fin}

        occupied?(segments, fin_offset, rcv_nxt) ->
          {segments, pending_fin}

        fin_offset == 0 ->
          # An in-order FIN is ready to commit now and supersedes any
          # speculative out-of-order marker, regardless of marker order.
          {segments, fin_sequence}

        pending_fin != nil ->
          {segments, pending_fin}

        true ->
          {segments, fin_sequence}
      end
    else
      {segments, pending_fin}
    end
  end

  defp occupied?(segments, offset, rcv_nxt) do
    Enum.any?(segments, fn {sequence, _sequence_end, payload} ->
      start_offset = signed_offset(sequence, rcv_nxt)
      start_offset <= offset and offset < start_offset + byte_size(payload)
    end)
  end

  defp revoke_conflicting_fin(_segments, nil, _rcv_nxt), do: nil

  defp revoke_conflicting_fin(segments, pending_fin, rcv_nxt) do
    if occupied?(segments, signed_offset(pending_fin, rcv_nxt), rcv_nxt),
      do: nil,
      else: pending_fin
  end

  # RFC 9293 §3.10.7.4 trims portions outside the receive window, including
  # SYN and FIN controls. Thus offset == receive_window is outside; only a
  # bare FIN at RCV.NXT is accepted when the advertised window is zero.
  defp accepted_fin?(0, 0), do: true
  defp accepted_fin?(offset, receive_window), do: offset >= 0 and offset < receive_window

  defp drain(segments, pending_fin, rcv_nxt) do
    {delivered, segments, rcv_nxt} = drain_payload(segments, rcv_nxt, [])

    if pending_fin == rcv_nxt do
      %{
        delivered: IO.iodata_to_binary(Enum.reverse(delivered)),
        fin?: true,
        fin_sequence: nil,
        out_of_order_segments: [],
        rcv_nxt: Sequence.wrap(rcv_nxt + 1)
      }
    else
      %{
        delivered: IO.iodata_to_binary(Enum.reverse(delivered)),
        fin?: false,
        fin_sequence: pending_fin,
        out_of_order_segments: segments,
        rcv_nxt: rcv_nxt
      }
    end
  end

  defp drain_payload([{sequence, sequence_end, payload} | rest], sequence, delivered) do
    drain_payload(rest, sequence_end, [payload | delivered])
  end

  defp drain_payload(segments, rcv_nxt, delivered), do: {delivered, segments, rcv_nxt}

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
