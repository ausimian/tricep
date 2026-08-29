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

  test "coalesces overlapping queued data without replacing first-arriving bytes" do
    queued = receive([], nil, 100, 32, 105, "world")
    queued = receive(queued.out_of_order_segments, nil, 100, 32, 107, "rld!!")

    assert queued.out_of_order_segments == [{105, 112, "world!!"}]

    result = receive(queued.out_of_order_segments, nil, 100, 32, 100, "hello")

    assert result.delivered == "helloworld!!"
    assert result.rcv_nxt == 112
    assert result.out_of_order_segments == []
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

  defp wrap(sequence), do: Integer.mod(sequence, 0x1_0000_0000)
end
