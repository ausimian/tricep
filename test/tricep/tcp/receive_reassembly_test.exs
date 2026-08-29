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

  test "queues a FIN carried by out-of-order payload until its gap arrives" do
    queued = receive([], nil, 100, 32, 105, "world", [:ack, :fin])

    assert queued.out_of_order_segments == [{105, 110, "world"}]
    assert queued.fin_sequence == 110
    refute queued.fin?

    result = receive(queued.out_of_order_segments, queued.fin_sequence, 100, 32, 100, "hello")

    assert result.delivered == "helloworld"
    assert result.rcv_nxt == 111
    assert result.fin?
    assert result.fin_sequence == nil
    assert result.out_of_order_segments == []
  end

  test "queues a bare out-of-order FIN and consumes it after queued data drains" do
    queued = receive([], nil, 100, 32, 105, <<>>, [:ack, :fin])

    assert queued.out_of_order_segments == []
    assert queued.fin_sequence == 105

    result = receive([], queued.fin_sequence, 100, 32, 100, "hello")

    assert result.delivered == "hello"
    assert result.rcv_nxt == 106
    assert result.fin?
  end

  test "trims duplicated payload before an overlapping FIN marker" do
    result = receive([], nil, 105, 8, 100, "abcdef", [:ack, :fin])

    assert result.delivered == "f"
    assert result.rcv_nxt == 107
    assert result.fin?
    assert result.fin_sequence == nil
  end

  test "does not duplicate queued data or a queued FIN on retransmission" do
    first = receive([], nil, 100, 32, 105, "world", [:ack, :fin])

    duplicate =
      receive(
        first.out_of_order_segments,
        first.fin_sequence,
        100,
        32,
        105,
        "world",
        [:ack, :fin]
      )

    assert duplicate.out_of_order_segments == [{105, 110, "world"}]
    assert duplicate.fin_sequence == 110

    result =
      receive(
        duplicate.out_of_order_segments,
        duplicate.fin_sequence,
        100,
        32,
        100,
        "hello"
      )

    assert result.delivered == "helloworld"
    assert result.rcv_nxt == 111
    assert result.fin?
  end

  test "revokes a queued FIN when later data occupies its marker" do
    pending_fin = receive([], nil, 100, 32, 105, <<>>, [:ack, :fin])

    assert pending_fin.fin_sequence == 105

    result =
      receive(
        pending_fin.out_of_order_segments,
        pending_fin.fin_sequence,
        100,
        32,
        100,
        "helloworld"
      )

    assert result.delivered == "helloworld"
    assert result.rcv_nxt == 110
    assert result.fin_sequence == nil
    refute result.fin?
    assert result.out_of_order_segments == []
  end

  test "rejects a FIN whose sequence number is already occupied by queued data" do
    queued = receive([], nil, 100, 32, 105, "world")

    conflicting_fin =
      receive(queued.out_of_order_segments, nil, 100, 32, 107, <<>>, [:ack, :fin])

    assert conflicting_fin.fin_sequence == nil
    assert conflicting_fin.out_of_order_segments == [{105, 110, "world"}]

    result = receive(conflicting_fin.out_of_order_segments, nil, 100, 32, 100, "hello")

    assert result.delivered == "helloworld"
    assert result.rcv_nxt == 110
    refute result.fin?
  end

  test "retains post-FIN queued data until the FIN commits and purges it" do
    queued = receive([], nil, 100, 32, 105, "world")

    pending_fin =
      receive(queued.out_of_order_segments, nil, 100, 32, 103, <<>>, [:ack, :fin])

    assert pending_fin.fin_sequence == 103
    assert pending_fin.out_of_order_segments == [{105, 110, "world"}]

    result =
      receive(
        pending_fin.out_of_order_segments,
        pending_fin.fin_sequence,
        100,
        32,
        100,
        "abc"
      )

    assert result.delivered == "abc"
    assert result.rcv_nxt == 104
    assert result.fin?
    assert result.out_of_order_segments == []
  end

  test "an accepted FIN at a queued range end drains the preceding data first" do
    queued = receive([], nil, 100, 32, 105, "world")

    pending_fin =
      receive(queued.out_of_order_segments, nil, 100, 32, 110, <<>>, [:ack, :fin])

    assert pending_fin.fin_sequence == 110
    assert pending_fin.out_of_order_segments == [{105, 110, "world"}]

    result =
      receive(
        pending_fin.out_of_order_segments,
        pending_fin.fin_sequence,
        100,
        32,
        100,
        "hello"
      )

    assert result.delivered == "helloworld"
    assert result.rcv_nxt == 111
    assert result.fin?
  end

  test "enforces queued FIN boundaries across sequence wrap" do
    queued = receive([], nil, 0xFFFFFFFC, 16, 0xFFFFFFFE, "wxyz")

    pending_fin =
      receive(
        queued.out_of_order_segments,
        nil,
        0xFFFFFFFC,
        16,
        2,
        <<>>,
        [:ack, :fin]
      )

    result =
      receive(
        pending_fin.out_of_order_segments,
        pending_fin.fin_sequence,
        0xFFFFFFFC,
        16,
        0xFFFFFFFC,
        "ab"
      )

    assert result.delivered == "abwxyz"
    assert result.rcv_nxt == 3
    assert result.fin?
  end

  test "keeps the first accepted FIN when a duplicate or conflicting FIN arrives" do
    first = receive([], nil, 100, 32, 105, <<>>, [:ack, :fin])

    duplicate = receive([], first.fin_sequence, 100, 32, 105, <<>>, [:ack, :fin])
    conflict = receive([], duplicate.fin_sequence, 100, 32, 106, <<>>, [:ack, :fin])

    assert duplicate.fin_sequence == 105
    assert conflict.fin_sequence == 105
    assert conflict.out_of_order_segments == []
  end

  test "an in-order FIN supersedes a stale speculative FIN marker" do
    stale = receive([], nil, 100, 32, 110, <<>>, [:ack, :fin])
    duplicate = receive([], stale.fin_sequence, 100, 32, 110, <<>>, [:ack, :fin])

    assert duplicate.fin_sequence == 110

    drained = receive([], duplicate.fin_sequence, 100, 32, 100, "hello")

    assert drained.rcv_nxt == 105
    assert drained.fin_sequence == 110

    real_fin =
      receive(
        drained.out_of_order_segments,
        drained.fin_sequence,
        drained.rcv_nxt,
        32,
        drained.rcv_nxt,
        <<>>,
        [:ack, :fin]
      )

    assert real_fin.delivered == <<>>
    assert real_fin.rcv_nxt == 106
    assert real_fin.fin?
    assert real_fin.fin_sequence == nil
  end

  test "an in-order FIN supersedes a speculative marker across sequence wrap" do
    stale = receive([], nil, 0xFFFFFFFC, 16, 2, <<>>, [:ack, :fin])
    duplicate = receive([], stale.fin_sequence, 0xFFFFFFFC, 16, 2, <<>>, [:ack, :fin])

    drained = receive([], duplicate.fin_sequence, 0xFFFFFFFC, 16, 0xFFFFFFFC, "ab")

    assert drained.rcv_nxt == 0xFFFFFFFE
    assert drained.fin_sequence == 2

    real_fin =
      receive(
        drained.out_of_order_segments,
        drained.fin_sequence,
        drained.rcv_nxt,
        16,
        drained.rcv_nxt,
        <<>>,
        [:ack, :fin]
      )

    assert real_fin.rcv_nxt == 0xFFFFFFFF
    assert real_fin.fin?
    assert real_fin.fin_sequence == nil
  end

  test "defers a FIN at the right receive-window edge until it is retransmitted" do
    data_and_fin = receive([], nil, 100, 5, 100, "hello", [:ack, :fin])

    assert data_and_fin.delivered == "hello"
    assert data_and_fin.rcv_nxt == 105
    refute data_and_fin.fin?
    assert data_and_fin.fin_sequence == nil

    fin = receive([], nil, data_and_fin.rcv_nxt, 0, 105, <<>>, [:ack, :fin])

    assert fin.delivered == <<>>
    assert fin.rcv_nxt == 106
    assert fin.fin?
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
end
