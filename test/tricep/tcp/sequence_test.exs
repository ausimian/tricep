defmodule Tricep.Tcp.SequenceTest do
  use ExUnit.Case, async: true

  alias Tricep.Tcp.Sequence

  describe "serial-number ordering" do
    test "orders adjacent values across the 32-bit wrap boundary" do
      assert Sequence.gt?(0, 0xFFFFFFFF)
      assert Sequence.lt?(0xFFFFFFFF, 0)
      assert Sequence.lte?(0xFFFFFFFF, 0)
      assert Sequence.gte?(0, 0xFFFFFFFF)
      assert Sequence.distance(0xFFFFFFFF, 1) == 2
    end

    test "keeps ordering and distance coherent around every generated wrap point" do
      for offset <- 0..1023 do
        before_wrap = Sequence.wrap(0xFFFFFFFF - offset)
        after_wrap = Sequence.wrap(before_wrap + 1)

        assert Sequence.gt?(after_wrap, before_wrap)
        assert Sequence.distance(before_wrap, after_wrap) == 1
      end
    end
  end

  describe "receive-window admission" do
    test "accepts a payload which crosses the wrap boundary" do
      segment = %{seq: 0xFFFFFFFE, flags: [:ack], payload: <<1, 2, 3>>}

      assert Sequence.acceptable?(segment, 0xFFFFFFFD, 8)
    end

    test "only accepts a pure FIN at RCV.NXT when the window is zero" do
      fin = %{seq: 12, flags: [:ack, :fin], payload: <<>>}
      payload = %{seq: 12, flags: [:ack], payload: <<1>>}

      assert Sequence.acceptable?(fin, 12, 0)
      refute Sequence.acceptable?(payload, 12, 0)
    end
  end
end
