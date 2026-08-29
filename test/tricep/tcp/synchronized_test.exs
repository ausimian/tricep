defmodule Tricep.Tcp.SynchronizedTest do
  use ExUnit.Case, async: true

  alias Tricep.Tcp
  alias Tricep.Tcp.Synchronized
  alias Tricep.Tcp.Tcb

  @pair {{<<0::128>>, 1234}, {<<1::128>>, 4321}}

  setup do
    tcb = %Tcb{
      iss: 0,
      snd_una: 100,
      snd_nxt: 110,
      snd_wnd: 1024,
      irs: 0,
      rcv_nxt: 0xFFFFFFFF,
      rcv_wnd: 8,
      rcv_adv_wnd: 8,
      rcv_right_edge: 7,
      rcv_mss: 1280,
      snd_mss: 1280,
      rcv_wnd_scale: 0,
      snd_wnd_scale: 0,
      window_scaling_negotiated: false
    }

    %{tcb: tcb}
  end

  test "admits a valid ACK across the receive sequence wrap", %{tcb: tcb} do
    segment = Tcp.build_segment(@pair, 0xFFFFFFFF, 110, [:ack], 1024)

    assert {:ok, %{seq: 0xFFFFFFFF, ack: 110}} =
             Synchronized.process(tcb, segment, validate_ack?: true)
  end

  test "gives an acceptable reset precedence over ACK validation", %{tcb: tcb} do
    segment = Tcp.build_segment(@pair, 0xFFFFFFFF, 111, [:rst, :ack], 1024)

    assert Synchronized.process(tcb, segment, validate_ack?: true) == :acceptable_reset
  end

  test "rejects resets outside the receive window", %{tcb: tcb} do
    segment = Tcp.build_segment(@pair, 32, 0, [:rst], 1024)

    assert Synchronized.process(tcb, segment) == :unacceptable_reset
  end

  test "rejects ACKs that acknowledge unsent data when requested", %{tcb: tcb} do
    segment = Tcp.build_segment(@pair, 0xFFFFFFFF, 111, [:ack], 1024)

    assert Synchronized.process(tcb, segment, validate_ack?: true) == :invalid_ack
  end

  test "keeps state-specific ACK policy explicit", %{tcb: tcb} do
    segment = Tcp.build_segment(@pair, 0xFFFFFFFF, 111, [:ack], 1024)

    assert {:ok, %{ack: 111}} = Synchronized.process(tcb, segment)
  end
end
