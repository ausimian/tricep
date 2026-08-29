defmodule Tricep.Tcp.Synchronized do
  @moduledoc false

  # Internal admission pipeline shared by synchronized TCP states. It preserves
  # pre-#111 RST-before-window processing before data and FIN effects. That
  # diverges from RFC 9293/RFC 5961 out-of-window silent-drop and challenge-ACK
  # behavior; bug #97 owns the correction.

  alias Tricep.Tcp
  alias Tricep.Tcp.Tcb

  @type outcome ::
          {:ok, Tcp.parsed_segment()}
          | :malformed
          | :acceptable_reset
          | :unacceptable_reset
          | :unacceptable_segment
          | :invalid_ack

  # Requires the TCB fields consumed by receive-window and ACK validation.
  def process(%Tcb{} = tcb, segment, opts \\ []) when is_binary(segment) do
    validate_ack? = Keyword.get(opts, :validate_ack?, false)

    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: sequence, ack: acknowledgment} = parsed ->
        classify(
          tcb,
          parsed,
          :rst in flags,
          :ack in flags,
          sequence,
          acknowledgment,
          validate_ack?
        )

      _ ->
        :malformed
    end
  end

  defp classify(tcb, _segment, true, _ack?, sequence, _acknowledgment, _validate_ack?) do
    if Tcb.acceptable_reset?(tcb, sequence), do: :acceptable_reset, else: :unacceptable_reset
  end

  defp classify(tcb, segment, false, ack?, _sequence, acknowledgment, validate_ack?) do
    cond do
      not Tcb.acceptable_segment?(tcb, segment) -> :unacceptable_segment
      validate_ack? and Tcb.invalid_ack?(tcb, ack?, acknowledgment) -> :invalid_ack
      true -> {:ok, segment}
    end
  end
end
