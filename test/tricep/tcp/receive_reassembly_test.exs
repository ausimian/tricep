defmodule Tricep.Tcp.ReceiveReassemblyTest do
  use ExUnit.Case, async: true

  alias Tricep.Tcp.ReceiveReassembly

  test "trims an already delivered prefix and retains the new suffix" do
    result = receive([], nil, 105, 20, 100, "abcdefghij")

    assert result.delivered == "fghij"
    assert result.rcv_nxt == 110
    assert result.out_of_order_segments == []
    refute result.fin?
  end

  test "clips a segment at both receive-window edges" do
    result = receive([], nil, 100, 5, 98, "abcdefghij")

    assert result.delivered == "cdefg"
    assert result.rcv_nxt == 105
    assert result.out_of_order_segments == []
  end

  test "clips receive overlaps across the 32-bit sequence wrap" do
    result = receive([], nil, 0xFFFFFFFE, 4, 0xFFFFFFFC, "abcdef")

    assert result.delivered == "cdef"
    assert result.rcv_nxt == 2
    assert result.out_of_order_segments == []
  end

  test "keeps overlapping queued data in ordered chunks without replacing first-arriving bytes" do
    queued = receive([], nil, 100, 32, 105, "world")
    queued = receive(queued.out_of_order_segments, nil, 100, 32, 107, "rld!!")

    assert queued.out_of_order_segments == [{105, 110, "world"}, {110, 112, "!!"}]

    result = receive(queued.out_of_order_segments, nil, 100, 32, 100, "hello")

    assert result.delivered == "helloworld!!"
    assert result.rcv_nxt == 112
    assert result.out_of_order_segments == []
  end

  test "stores ascending one-byte and MSS chunks separately until their front gap arrives" do
    max_fragments = ReceiveReassembly.max_fragment_count()

    for payload_size <- [1, 510] do
      receive_window = max_fragments * payload_size + 1
      payload = :binary.copy("x", payload_size)

      queued =
        Enum.reduce(0..(max_fragments - 1), empty_result(), fn index, result ->
          receive(
            result.out_of_order_segments,
            result.pending_fin,
            0,
            receive_window,
            1 + index * payload_size,
            payload
          )
        end)

      assert length(queued.out_of_order_segments) == max_fragments

      assert Enum.all?(queued.out_of_order_segments, fn {_start, _ending, chunk} ->
               byte_size(chunk) == payload_size
             end)

      drained =
        receive(queued.out_of_order_segments, queued.pending_fin, 0, receive_window, 0, "a")

      assert drained.delivered == "a" <> :binary.copy("x", max_fragments * payload_size)
      assert drained.rcv_nxt == max_fragments * payload_size + 1
      assert drained.out_of_order_segments == []
    end
  end

  test "copies retained payload slices away from their source packet binary" do
    source_packet = :binary.copy("x", 65_535)

    queued = receive([], nil, 0, 128, 64, source_packet)

    assert [{64, 128, retained}] = queued.out_of_order_segments
    assert byte_size(retained) == 64
    # The retained slice must not keep the 65 KiB packet parent alive.
    assert :binary.referenced_byte_size(retained) < :binary.referenced_byte_size(source_packet)

    duplicate = receive(queued.out_of_order_segments, nil, 0, 128, 64, :binary.copy("y", 64))

    # First-arrival overlap semantics retain the original bytes.
    assert duplicate.out_of_order_segments == [{64, 128, :binary.copy("x", 64)}]
  end

  test "delivers an in-order packet without retaining a chunk" do
    source_packet = :binary.copy("x", 65_535)

    result = receive([], nil, 0, byte_size(source_packet), 0, source_packet)

    assert result.out_of_order_segments == []
    assert result.evicted_count == 0
    assert result.delivered == source_packet
  end

  test "evicts the highest tail by bytes while retaining front-recovery capacity" do
    receive_window = 97
    local_mss = 16
    byte_budget = receive_window - local_mss

    for rcv_nxt <- [0, 0xFFFFFFE0] do
      {queued, evicted_count} =
        Enum.reduce(1..(receive_window - 1)//local_mss, {empty_result(), 0}, fn start,
                                                                                {result, total} ->
          payload_size = min(local_mss, receive_window - start)

          result =
            ReceiveReassembly.receive(
              result.out_of_order_segments,
              result.pending_fin,
              rcv_nxt,
              receive_window,
              byte_budget,
              %{
                flags: [:ack],
                payload: :binary.copy("x", payload_size),
                seq: wrap(rcv_nxt + start)
              }
            )

          {result, total + result.evicted_count}
        end)

      queued_bytes =
        Enum.reduce(queued.out_of_order_segments, 0, fn {_start, _ending, payload}, total ->
          total + byte_size(payload)
        end)

      assert queued_bytes <= byte_budget
      assert evicted_count == 1

      assert queued.out_of_order_segments == [
               {wrap(rcv_nxt + 1), wrap(rcv_nxt + 17), :binary.copy("x", 16)},
               {wrap(rcv_nxt + 17), wrap(rcv_nxt + 33), :binary.copy("x", 16)},
               {wrap(rcv_nxt + 33), wrap(rcv_nxt + 49), :binary.copy("x", 16)},
               {wrap(rcv_nxt + 49), wrap(rcv_nxt + 65), :binary.copy("x", 16)},
               {wrap(rcv_nxt + 65), wrap(rcv_nxt + 81), :binary.copy("x", 16)}
             ]

      front =
        ReceiveReassembly.receive(
          queued.out_of_order_segments,
          queued.pending_fin,
          rcv_nxt,
          receive_window - queued_bytes,
          byte_budget,
          %{flags: [:ack], payload: :binary.copy("a", local_mss), seq: rcv_nxt}
        )

      assert front.delivered == "a" <> :binary.copy("x", 80)
      assert front.rcv_nxt == wrap(rcv_nxt + 81)
      assert front.out_of_order_segments == []

      recovered =
        ReceiveReassembly.receive(
          front.out_of_order_segments,
          front.pending_fin,
          front.rcv_nxt,
          receive_window - byte_size(front.delivered),
          receive_window - byte_size(front.delivered) - local_mss,
          %{flags: [:ack], payload: :binary.copy("x", 16), seq: front.rcv_nxt}
        )

      assert recovered.delivered == :binary.copy("x", 16)
      assert recovered.rcv_nxt == wrap(rcv_nxt + receive_window)
      assert recovered.out_of_order_segments == []
    end
  end

  test "bounds alternating one-byte fragments and admits retransmissions after draining" do
    max_fragments = ReceiveReassembly.max_fragment_count()
    receive_window = max_fragments * 2 + 2

    queued =
      Enum.reduce(1..(max_fragments + 16), empty_result(), fn index, result ->
        receive(
          result.out_of_order_segments,
          result.pending_fin,
          0,
          receive_window,
          index * 2 - 1,
          "x"
        )
      end)

    assert length(queued.out_of_order_segments) == max_fragments

    assert Enum.all?(queued.out_of_order_segments, fn {_start, _ending, payload} ->
             payload == "x"
           end)

    drained = receive(queued.out_of_order_segments, queued.pending_fin, 0, receive_window, 0, "a")

    assert drained.delivered == "ax"
    assert drained.rcv_nxt == 2
    assert length(drained.out_of_order_segments) == max_fragments - 1

    retransmitted =
      receive(
        drained.out_of_order_segments,
        drained.pending_fin,
        drained.rcv_nxt,
        receive_window,
        max_fragments * 2 + 1,
        "z"
      )

    assert length(retransmitted.out_of_order_segments) == max_fragments

    assert Enum.any?(retransmitted.out_of_order_segments, fn {start, _ending, payload} ->
             start == max_fragments * 2 + 1 and payload == "z"
           end)
  end

  test "delivers a non-abutting full-size receive-front segment at the limit" do
    max_fragments = ReceiveReassembly.max_fragment_count()
    first_queued = 1024
    front_payload = String.duplicate("a", 512)
    receive_window = first_queued + max_fragments * 2 + 2
    dropped_sequence = first_queued + max_fragments * 2 + 1

    queued =
      Enum.reduce(0..(max_fragments - 1), empty_result(), fn index, result ->
        receive(
          result.out_of_order_segments,
          result.pending_fin,
          0,
          receive_window,
          first_queued + index * 2,
          "x"
        )
      end)

    assert length(queued.out_of_order_segments) == max_fragments

    dropped =
      receive(
        queued.out_of_order_segments,
        queued.pending_fin,
        0,
        receive_window,
        dropped_sequence,
        "z"
      )

    refute Enum.any?(dropped.out_of_order_segments, fn {start, _ending, payload} ->
             start == dropped_sequence and payload == "z"
           end)

    assert dropped.evicted_count == 1

    advanced =
      receive(
        dropped.out_of_order_segments,
        dropped.pending_fin,
        0,
        receive_window,
        0,
        front_payload
      )

    assert advanced.delivered == front_payload
    assert advanced.rcv_nxt == byte_size(front_payload)
    assert length(advanced.out_of_order_segments) == max_fragments

    filled =
      receive(
        advanced.out_of_order_segments,
        advanced.pending_fin,
        advanced.rcv_nxt,
        receive_window,
        advanced.rcv_nxt,
        String.duplicate("b", first_queued - byte_size(front_payload))
      )

    assert filled.delivered ==
             String.duplicate("b", first_queued - byte_size(front_payload)) <> "x"

    assert filled.rcv_nxt == first_queued + 1
    assert length(filled.out_of_order_segments) == max_fragments - 1

    retransmitted =
      receive(
        filled.out_of_order_segments,
        filled.pending_fin,
        filled.rcv_nxt,
        receive_window,
        dropped_sequence,
        "z"
      )

    assert Enum.any?(retransmitted.out_of_order_segments, fn {start, _ending, payload} ->
             start == dropped_sequence and payload == "z"
           end)
  end

  test "advances receive-front data at the fragment limit across sequence wrap" do
    max_fragments = ReceiveReassembly.max_fragment_count()
    rcv_nxt = 0xFFFFFF00
    first_queued = 512
    receive_window = first_queued + max_fragments * 2 + 2

    queued =
      Enum.reduce(0..(max_fragments - 1), empty_result(), fn index, result ->
        receive(
          result.out_of_order_segments,
          result.pending_fin,
          rcv_nxt,
          receive_window,
          wrap(rcv_nxt + first_queued + index * 2),
          "x"
        )
      end)

    advanced =
      receive(
        queued.out_of_order_segments,
        queued.pending_fin,
        rcv_nxt,
        receive_window,
        rcv_nxt,
        String.duplicate("a", 48)
      )

    assert advanced.delivered == String.duplicate("a", 48)
    assert advanced.rcv_nxt == wrap(rcv_nxt + 48)
    assert length(advanced.out_of_order_segments) == max_fragments
    assert {first_start, _first_end, "x"} = hd(advanced.out_of_order_segments)
    assert first_start == wrap(rcv_nxt + first_queued)
  end

  test "drops a pending FIN when fragment eviction removes its payload tail" do
    max_fragments = ReceiveReassembly.max_fragment_count()
    first_queued = 100
    receive_window = first_queued + max_fragments * 2 + 2
    fin_payload_start = first_queued + max_fragments * 2 + 1

    queued =
      Enum.reduce(0..(max_fragments - 1), empty_result(), fn index, result ->
        receive(
          result.out_of_order_segments,
          result.pending_fin,
          0,
          receive_window,
          first_queued + index * 2,
          "x"
        )
      end)

    evicted_fin =
      receive(
        queued.out_of_order_segments,
        queued.pending_fin,
        0,
        receive_window,
        fin_payload_start,
        "z",
        [:ack, :fin]
      )

    assert evicted_fin.pending_fin == nil
    assert evicted_fin.fin_sequence == nil

    refute Enum.any?(evicted_fin.out_of_order_segments, fn {start, _ending, payload} ->
             start == fin_payload_start and payload == "z"
           end)
  end

  test "counts gap-filling chunks against the fragment limit" do
    max_fragments = ReceiveReassembly.max_fragment_count()
    receive_window = max_fragments * 2 + 2

    queued =
      Enum.reduce(1..max_fragments, empty_result(), fn index, result ->
        receive(
          result.out_of_order_segments,
          result.pending_fin,
          0,
          receive_window,
          index * 2 - 1,
          "x"
        )
      end)

    merged =
      receive(
        queued.out_of_order_segments,
        queued.pending_fin,
        0,
        receive_window,
        1,
        String.duplicate("z", max_fragments * 2 - 1)
      )

    expected =
      for offset <- 1..max_fragments, into: <<>> do
        if rem(offset, 2) == 1, do: "x", else: "z"
      end

    assert length(merged.out_of_order_segments) == max_fragments

    expected_chunks =
      for offset <- 1..max_fragments do
        {offset, offset + 1, if(rem(offset, 2) == 1, do: "x", else: "z")}
      end

    assert merged.out_of_order_segments == expected_chunks

    drained = receive(merged.out_of_order_segments, merged.pending_fin, 0, receive_window, 0, "a")

    assert drained.delivered == "a" <> expected
    assert drained.rcv_nxt == max_fragments + 1
    assert drained.out_of_order_segments == []
  end

  test "bounds alternating fragments across the sequence-number wrap" do
    max_fragments = ReceiveReassembly.max_fragment_count()
    receive_window = max_fragments * 2 + 2
    rcv_nxt = 0xFFFFFF00

    queued =
      Enum.reduce(1..(max_fragments + 16), empty_result(), fn index, result ->
        receive(
          result.out_of_order_segments,
          result.pending_fin,
          rcv_nxt,
          receive_window,
          wrap(rcv_nxt + index * 2 - 1),
          "x"
        )
      end)

    assert length(queued.out_of_order_segments) == max_fragments
    assert {first_start, _first_end, "x"} = hd(queued.out_of_order_segments)
    assert {last_start, _last_end, "x"} = List.last(queued.out_of_order_segments)
    assert first_start == wrap(rcv_nxt + 1)
    assert last_start == wrap(rcv_nxt + max_fragments * 2 - 1)

    drained =
      receive(
        queued.out_of_order_segments,
        queued.pending_fin,
        rcv_nxt,
        receive_window,
        rcv_nxt,
        "a"
      )

    assert drained.delivered == "ax"
    assert drained.rcv_nxt == wrap(rcv_nxt + 2)
    assert length(drained.out_of_order_segments) == max_fragments - 1
  end

  test "commits an out-of-order payload-carried FIN once its gap arrives" do
    queued = receive([], nil, 100, 32, 105, "world", [:ack, :fin])

    assert queued.out_of_order_segments == [{105, 110, "world"}]
    assert queued.pending_fin == {110, 105}
    assert queued.fin_sequence == 110
    refute queued.fin?

    result = receive(queued.out_of_order_segments, queued.pending_fin, 100, 32, 100, "hello")

    assert result.delivered == "helloworld"
    assert result.rcv_nxt == 111
    assert result.fin?
    assert result.fin_sequence == nil
    assert result.pending_fin == nil
    assert result.out_of_order_segments == []
  end

  test "commits a payload-carried FIN whose retained range spans adjacent chunks" do
    first = receive([], nil, 100, 32, 105, "wo")

    queued =
      receive(
        first.out_of_order_segments,
        first.pending_fin,
        100,
        32,
        107,
        "rld",
        [:ack, :fin]
      )

    assert queued.out_of_order_segments == [{105, 107, "wo"}, {107, 110, "rld"}]
    assert queued.pending_fin == {110, 107}

    result = receive(queued.out_of_order_segments, queued.pending_fin, 100, 32, 100, "hello")

    assert result.delivered == "helloworld"
    assert result.rcv_nxt == 111
    assert result.fin?
    assert result.out_of_order_segments == []
  end

  test "drops a bare out-of-order FIN until it is retransmitted in order" do
    bare_fin = receive([], nil, 100, 32, 105, <<>>, [:ack, :fin])

    assert bare_fin.out_of_order_segments == []
    assert bare_fin.pending_fin == nil
    assert bare_fin.fin_sequence == nil

    data = receive([], bare_fin.pending_fin, 100, 32, 100, "hello")

    assert data.delivered == "hello"
    assert data.rcv_nxt == 105
    refute data.fin?
    assert data.pending_fin == nil

    retransmitted = receive([], nil, data.rcv_nxt, 32, data.rcv_nxt, <<>>, [:ack, :fin])

    assert retransmitted.fin?
    assert retransmitted.rcv_nxt == 106
  end

  test "trims duplicated payload before an overlapping FIN marker" do
    result = receive([], nil, 105, 8, 100, "abcdef", [:ack, :fin])

    assert result.delivered == "f"
    assert result.rcv_nxt == 107
    assert result.fin?
    assert result.fin_sequence == nil
  end

  test "does not duplicate queued data or a queued payload-carried FIN on retransmission" do
    first = receive([], nil, 100, 32, 105, "world", [:ack, :fin])

    duplicate =
      receive(
        first.out_of_order_segments,
        first.pending_fin,
        100,
        32,
        105,
        "world",
        [:ack, :fin]
      )

    assert duplicate.out_of_order_segments == [{105, 110, "world"}]
    assert duplicate.pending_fin == {110, 105}

    result =
      receive(duplicate.out_of_order_segments, duplicate.pending_fin, 100, 32, 100, "hello")

    assert result.delivered == "helloworld"
    assert result.rcv_nxt == 111
    assert result.fin?
  end

  test "payload extending past a FIN marker invalidates its hint in either arrival order" do
    hinted = receive([], nil, 100, 32, 105, "world", [:ack, :fin])

    after_hint =
      receive(hinted.out_of_order_segments, hinted.pending_fin, 100, 32, 110, "suffix")

    assert after_hint.pending_fin == nil

    first_data = receive([], nil, 100, 32, 110, "suffix")

    after_data =
      receive(
        first_data.out_of_order_segments,
        first_data.pending_fin,
        100,
        32,
        105,
        "world",
        [:ack, :fin]
      )

    assert after_data.pending_fin == nil
  end

  test "rejects a first payload-carried FIN marker before or inside queued data" do
    queued = receive([], nil, 100, 32, 105, "world")

    for marker <- [103, 105, 107] do
      rejected =
        receive(
          queued.out_of_order_segments,
          nil,
          100,
          32,
          marker - 1,
          "x",
          [:ack, :fin]
        )

      assert rejected.pending_fin == nil
    end

    accepted =
      receive(queued.out_of_order_segments, nil, 100, 32, 109, "d", [:ack, :fin])

    assert accepted.pending_fin == {110, 109}
  end

  test "uses the same queued-end boundary across sequence wrap" do
    queued = receive([], nil, 0xFFFFFFFC, 16, 0xFFFFFFFE, "wxyz")

    assert wrap(-1) == 0xFFFFFFFF

    for marker <- [0xFFFFFFFD, 0xFFFFFFFE, 0] do
      rejected =
        receive(
          queued.out_of_order_segments,
          nil,
          0xFFFFFFFC,
          16,
          wrap(marker - 1),
          "x",
          [:ack, :fin]
        )

      assert rejected.pending_fin == nil
    end

    accepted =
      receive(queued.out_of_order_segments, nil, 0xFFFFFFFC, 16, 1, "z", [:ack, :fin])

    assert accepted.pending_fin == {2, 1}
  end

  test "a current payload-carried FIN supersedes a stale hint and closes immediately" do
    stale = receive([], nil, 100, 32, 104, "o", [:ack, :fin])

    result =
      receive(
        stale.out_of_order_segments,
        stale.pending_fin,
        100,
        32,
        100,
        "helloworld",
        [:ack, :fin]
      )

    assert result.delivered == "helloworld"
    assert result.rcv_nxt == 111
    assert result.fin?
    assert result.pending_fin == nil
  end

  test "a current payload-carried FIN supersedes a stale hint across sequence wrap" do
    stale = receive([], nil, 0xFFFFFFFC, 16, 0xFFFFFFFD, "b", [:ack, :fin])

    result =
      receive(
        stale.out_of_order_segments,
        stale.pending_fin,
        0xFFFFFFFC,
        16,
        0xFFFFFFFC,
        "abcd",
        [:ack, :fin]
      )

    assert result.delivered == "abcd"
    assert result.rcv_nxt == 1
    assert result.fin?
    assert result.pending_fin == nil
  end

  test "accepts a FIN at the right receive-window edge with its payload" do
    data_and_fin = receive([], nil, 100, 5, 100, "hello", [:ack, :fin])

    assert data_and_fin.delivered == "hello"
    assert data_and_fin.rcv_nxt == 106
    assert data_and_fin.fin?
    assert data_and_fin.fin_sequence == nil
  end

  test "accepts a bare FIN at RCV.NXT when the receive window is zero" do
    result = receive([], nil, 100, 0, 100, <<>>, [:ack, :fin])

    assert result.delivered == <<>>
    assert result.rcv_nxt == 101
    assert result.fin?
  end

  defp receive(segments, pending_fin, rcv_nxt, receive_window, sequence, payload, flags \\ [:ack]) do
    ReceiveReassembly.receive(segments, pending_fin, rcv_nxt, receive_window, %{
      flags: flags,
      payload: payload,
      seq: sequence
    })
  end

  defp empty_result do
    %{out_of_order_segments: [], pending_fin: nil}
  end

  defp wrap(sequence), do: Integer.mod(sequence, 0x1_0000_0000)
end
