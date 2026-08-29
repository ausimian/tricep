defmodule Tricep.Tcp.TcbTest do
  use ExUnit.Case, async: true

  alias Tricep.Tcp.Tcb

  test "initializes an active open across the sequence wrap boundary" do
    tcb = Tcb.begin_active_open(%Tcb{}, 0xFFFFFFFF, 4096)

    assert tcb.iss == 0xFFFFFFFF
    assert tcb.snd_una == 0xFFFFFFFF
    assert tcb.snd_nxt == 0
    assert tcb.snd_wnd == 0
    assert tcb.rcv_wnd == 4096
  end

  test "completes an active SYN-ACK transition without scaling its window" do
    tcb =
      Tcb.establish_active(%Tcb{}, %{
        initial_receive_sequence: 0xFFFFFFFF,
        acknowledgment: 10,
        send_window: 512,
        send_mss: 1200,
        receive_window_scale: 4,
        send_window_scale: 3,
        window_scaling_negotiated: true
      })

    assert tcb.irs == 0xFFFFFFFF
    assert tcb.rcv_nxt == 0
    assert tcb.snd_una == 10
    assert tcb.snd_wnd == 512
    assert tcb.snd_mss == 1200
    assert tcb.rcv_wnd_scale == 4
    assert tcb.snd_wnd_scale == 3
    assert tcb.window_scaling_negotiated
  end

  test "advances send and receive sequence numbers across the wrap boundary" do
    tcb = %Tcb{snd_nxt: 0xFFFFFFFF, rcv_nxt: 0xFFFFFFFF}

    assert Tcb.advance_send(tcb, 1).snd_nxt == 0
    assert Tcb.advance_receive(tcb, 2).rcv_nxt == 1
  end

  test "classifies reset sequences across the wrap boundary" do
    tcb = %Tcb{rcv_nxt: 0xFFFFFFFF, rcv_wnd: 8}

    assert Tcb.reset_validation(tcb, 0xFFFFFFFF) == :exact
    assert Tcb.reset_validation(tcb, 0) == :in_window
    assert Tcb.reset_validation(tcb, 8) == :out_of_window
  end

  test "updates an acknowledgement and its scaled peer window together" do
    tcb = %Tcb{snd_una: 100, snd_nxt: 200, snd_wnd: 0, snd_wnd_scale: 3}

    updated = Tcb.acknowledge(tcb, 150, 512)

    assert updated.snd_una == 150
    assert updated.snd_wnd == 4096
    assert Tcb.send_window_available(updated) == 4046
  end

  test "accepts only in-flight sequences across the wrap boundary" do
    tcb = %Tcb{snd_una: 0xFFFFFFFE, snd_nxt: 2}

    assert Tcb.in_flight?(tcb, 0xFFFFFFFE)
    assert Tcb.in_flight?(tcb, 0xFFFFFFFF)
    assert Tcb.in_flight?(tcb, 0)
    assert Tcb.in_flight?(tcb, 1)
    refute Tcb.in_flight?(tcb, 2)
    refute Tcb.in_flight?(tcb, 0xFFFFFFFD)
  end

  test "only reduces send MSS for a smaller path MTU" do
    tcb = %Tcb{snd_mss: 1440}

    assert {:reduced, %Tcb{snd_mss: 1220}} =
             Tcb.update_send_mss_for_path_mtu(tcb, 1220, 1440)

    assert Tcb.update_send_mss_for_path_mtu(tcb, 1440, 1440) == :unchanged

    assert {:reduced, %Tcb{snd_mss: 1200}} =
             Tcb.update_send_mss_for_path_mtu(%Tcb{}, 1200, 1220)
  end

  test "refreshes a scaled advertised window without admitting beyond capacity" do
    tcb = %Tcb{
      rcv_nxt: 0xFFFFFFFE,
      rcv_wnd: 0,
      rcv_adv_wnd: 0,
      rcv_right_edge: nil,
      rcv_wnd_scale: 2,
      window_scaling_negotiated: true
    }

    advertised = Tcb.refresh_receive_window(tcb, 4099)

    assert advertised.rcv_adv_wnd == 4096
    assert advertised.rcv_wnd == 4096
    assert Tcb.advertised_receive_window(advertised) == 1024

    exhausted = advertised |> Tcb.advance_receive(10) |> Tcb.refresh_receive_window(0)

    assert exhausted.rcv_wnd == 0
    assert exhausted.rcv_adv_wnd == 0
    assert exhausted.rcv_right_edge == advertised.rcv_right_edge
  end
end
