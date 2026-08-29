defmodule Tricep.Tcp.Tcb do
  @moduledoc false

  # Internal ownership boundary: the TCB owns ISS/SND.* sequence state,
  # IRS/RCV.* receive-window state, and negotiated MSS/window-scale values.
  # Socket owns OTP/I-O adaptation, buffers, waiters, retransmission timers,
  # and API notifications; it stores this structure as `:tcb`.

  alias Tricep.Tcp
  alias Tricep.Tcp.Sequence

  import Bitwise
  require Tcp

  use TypedStruct

  @type sequence :: Sequence.sequence_number()

  typedstruct do
    field :iss, sequence() | nil, default: nil
    field :snd_una, sequence() | nil, default: nil
    field :snd_nxt, sequence() | nil, default: nil
    field :snd_wnd, non_neg_integer() | nil, default: nil
    field :irs, sequence() | nil, default: nil
    field :rcv_nxt, sequence() | nil, default: nil
    field :rcv_wnd, non_neg_integer() | nil, default: nil
    field :rcv_adv_wnd, non_neg_integer() | nil, default: nil
    field :rcv_right_edge, sequence() | nil, default: nil
    field :rcv_mss, non_neg_integer() | nil, default: nil
    field :snd_mss, non_neg_integer() | nil, default: nil
    field :rcv_wnd_scale, non_neg_integer(), default: 0
    field :snd_wnd_scale, non_neg_integer(), default: 0
    field :window_scaling_negotiated, boolean(), default: false
  end

  # Requires SND.NXT to be initialized when an ACK is present.
  def invalid_ack?(%__MODULE__{snd_nxt: send_next}, true, acknowledgment),
    do: Sequence.gt?(acknowledgment, send_next)

  def invalid_ack?(%__MODULE__{}, false, _acknowledgment), do: false

  # Classifies reset sequence numbers for the RFC 5961 receive path.
  # Requires initialized RCV.NXT and RCV.WND fields.
  @spec reset_validation(t(), sequence()) :: :exact | :in_window | :out_of_window
  def reset_validation(%__MODULE__{rcv_nxt: receive_next, rcv_wnd: receive_window}, sequence) do
    cond do
      sequence == receive_next -> :exact
      Sequence.in_window?(sequence, receive_next, receive_window) -> :in_window
      true -> :out_of_window
    end
  end

  # Requires initialized RCV.NXT and RCV.WND fields.
  def acceptable_segment?(%__MODULE__{rcv_nxt: receive_next, rcv_wnd: receive_window}, segment) do
    Sequence.acceptable?(segment, receive_next, receive_window)
  end

  # Initializes send and receive control fields after an active-open SYN.
  @spec begin_active_open(t(), sequence(), non_neg_integer()) :: t()
  def begin_active_open(%__MODULE__{} = tcb, initial_send_sequence, receive_window) do
    %{
      tcb
      | iss: initial_send_sequence,
        snd_una: initial_send_sequence,
        snd_nxt: Sequence.wrap(initial_send_sequence + 1),
        snd_wnd: 0,
        rcv_wnd: receive_window
    }
  end

  @type active_establishment :: %{
          required(:initial_receive_sequence) => sequence(),
          required(:acknowledgment) => sequence(),
          required(:send_window) => non_neg_integer(),
          required(:send_mss) => non_neg_integer(),
          required(:receive_window_scale) => non_neg_integer(),
          required(:send_window_scale) => non_neg_integer(),
          required(:window_scaling_negotiated) => boolean()
        }

  # Completes the active-open control transition for a valid SYN-ACK.
  @spec establish_active(t(), active_establishment()) :: t()
  def establish_active(
        %__MODULE__{} = tcb,
        %{
          initial_receive_sequence: initial_receive_sequence,
          acknowledgment: acknowledgment,
          send_window: send_window,
          send_mss: send_mss,
          receive_window_scale: receive_window_scale,
          send_window_scale: send_window_scale,
          window_scaling_negotiated: window_scaling_negotiated
        }
      ) do
    %{
      tcb
      | irs: initial_receive_sequence,
        rcv_nxt: Sequence.wrap(initial_receive_sequence + 1),
        snd_una: acknowledgment,
        # The window in a SYN or SYN-ACK is never scaled.
        snd_wnd: send_window,
        snd_mss: send_mss,
        rcv_wnd_scale: receive_window_scale,
        snd_wnd_scale: send_window_scale,
        window_scaling_negotiated: window_scaling_negotiated
    }
  end

  # Advances an initialized RCV.NXT through TCP's wrapping sequence space.
  def advance_receive(%__MODULE__{} = tcb, length) do
    %{tcb | rcv_nxt: Sequence.wrap(tcb.rcv_nxt + length)}
  end

  # Sets RCV.NXT after an already-validated in-order queued segment.
  @spec receive_next(t(), sequence()) :: t()
  def receive_next(%__MODULE__{} = tcb, sequence), do: %{tcb | rcv_nxt: sequence}

  # Advances an initialized SND.NXT through TCP's wrapping sequence space.
  def advance_send(%__MODULE__{} = tcb, length) do
    %{tcb | snd_nxt: Sequence.wrap(tcb.snd_nxt + length)}
  end

  # Updates SND.WND from the peer's unscaled 16-bit window field.
  @spec update_send_window(t(), non_neg_integer()) :: t()
  def update_send_window(%__MODULE__{} = tcb, window) do
    %{tcb | snd_wnd: window <<< tcb.snd_wnd_scale}
  end

  # Records an acceptable acknowledgement and its accompanying peer window.
  @spec acknowledge(t(), sequence(), non_neg_integer()) :: t()
  def acknowledge(%__MODULE__{} = tcb, acknowledgment, window) do
    tcb
    |> update_send_window(window)
    |> Map.put(:snd_una, acknowledgment)
  end

  # Applies an already-bounded MSS derived from a path-MTU update.
  @spec update_send_mss_for_path_mtu(t(), non_neg_integer(), non_neg_integer()) ::
          {:reduced, t()} | :unchanged
  def update_send_mss_for_path_mtu(%__MODULE__{} = tcb, path_mtu_mss, default_mss) do
    current_mss = tcb.snd_mss || default_mss

    if path_mtu_mss < current_mss do
      {:reduced, %{tcb | snd_mss: path_mtu_mss}}
    else
      :unchanged
    end
  end

  # Requires an initialized RCV.ADV.WND field.
  def advertised_receive_window(%__MODULE__{} = tcb) do
    tcb.rcv_adv_wnd >>> receive_window_scale(tcb)
  end

  # Returns the scale currently applicable to outgoing receive windows.
  @spec receive_window_scale(t()) :: non_neg_integer()
  def receive_window_scale(%__MODULE__{window_scaling_negotiated: true, rcv_wnd_scale: scale}),
    do: scale

  def receive_window_scale(%__MODULE__{}), do: 0

  # Caps the advertised receive window by buffer capacity.
  # Requires an initialized RCV.WND field.
  def receive_window(%__MODULE__{} = tcb, available_window) do
    min(tcb.rcv_wnd, available_window)
  end

  # Requires initialized SND.UNA, SND.NXT, and SND.WND fields.
  def send_window_available(%__MODULE__{} = tcb) do
    bytes_in_flight = Sequence.distance(tcb.snd_una, tcb.snd_nxt)
    max(0, tcb.snd_wnd - bytes_in_flight)
  end

  # Returns whether a quoted TCP sequence number identifies data that is still
  # in flight. ICMP error handling uses this to reject forged and stale
  # reports; the comparison is deliberately half-open, as required by RFC
  # 5927 section 4.1.
  @spec in_flight?(t(), sequence()) :: boolean()
  def in_flight?(%__MODULE__{snd_una: send_unacknowledged, snd_nxt: send_next}, sequence)
      when is_integer(send_unacknowledged) and is_integer(send_next) and is_integer(sequence) do
    Sequence.gte?(sequence, send_unacknowledged) and Sequence.lt?(sequence, send_next)
  end

  def in_flight?(%__MODULE__{}, _sequence), do: false

  # Requires initialized receive sequence and window fields.
  def refresh_receive_window(%__MODULE__{} = tcb, available_window, opts \\ []) do
    scale = receive_window_scale(tcb)

    reserve =
      if Keyword.get(opts, :reserve_scale_headroom?, false), do: (1 <<< scale) - 1, else: 0

    advertised_window =
      available_window
      |> max(0)
      |> Kernel.-(reserve)
      |> max(0)
      |> representable_window(scale)

    advertised_right_edge = Sequence.wrap(tcb.rcv_nxt + advertised_window)
    authorized_right_edge = later_right_edge(tcb.rcv_right_edge, advertised_right_edge)

    receive_window =
      min(window_to_right_edge(tcb.rcv_nxt, authorized_right_edge), available_window)

    %{
      tcb
      | rcv_wnd: receive_window,
        rcv_adv_wnd: advertised_window,
        rcv_right_edge: authorized_right_edge
    }
  end

  defp representable_window(window, scale) do
    scaled_window = window >>> scale

    scaled_window
    |> min(Tcp.max_window())
    |> then(&(&1 <<< scale))
  end

  defp later_right_edge(nil, candidate), do: candidate

  defp later_right_edge(current, candidate) do
    if Sequence.gt?(candidate, current), do: candidate, else: current
  end

  defp window_to_right_edge(receive_next, right_edge) do
    if Sequence.lt?(receive_next, right_edge),
      do: Sequence.distance(receive_next, right_edge),
      else: 0
  end
end
