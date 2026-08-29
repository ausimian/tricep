defmodule Tricep.Tcp.Synchronized do
  @moduledoc false

  # Internal admission pipeline shared by synchronized TCP states. RFC 5961
  # RST and SYN handling deliberately happens before state-specific effects so
  # every synchronized state applies the same challenge-ACK policy.

  alias Tricep.Tcp
  alias Tricep.Tcp.Tcb

  @type outcome ::
          {:ok, Tcp.parsed_segment()}
          | :malformed
          | :acceptable_reset
          | :challenge_ack
          | :silent_drop
          | :unacceptable_segment
          | :invalid_ack

  # Requires the TCB fields consumed by receive-window and ACK validation.
  def process(%Tcb{} = tcb, segment, opts \\ []) when is_binary(segment) do
    validate_ack? = Keyword.get(opts, :validate_ack?, false)

    case Tcp.parse_segment(segment) do
      %{flags: flags, seq: sequence, ack: acknowledgment} = parsed ->
        classify(tcb, parsed, flags, sequence, acknowledgment, validate_ack?)

      _ ->
        :malformed
    end
  end

  defp classify(tcb, segment, flags, sequence, acknowledgment, validate_ack?) do
    cond do
      :rst in flags ->
        reset_outcome(tcb, sequence)

      :syn in flags ->
        # RFC 5961 §4.2 requires a challenge ACK irrespective of SEG.SEQ, so
        # SYN classification deliberately precedes receive-window rejection.
        :challenge_ack

      not Tcb.acceptable_segment?(tcb, segment) ->
        :unacceptable_segment

      validate_ack? and Tcb.invalid_ack?(tcb, :ack in flags, acknowledgment) ->
        :invalid_ack

      true ->
        {:ok, segment}
    end
  end

  @spec reset_outcome(Tcb.t(), Tcb.sequence()) ::
          :acceptable_reset | :challenge_ack | :silent_drop
  def reset_outcome(%Tcb{} = tcb, sequence) do
    case Tcb.reset_validation(tcb, sequence) do
      :exact -> :acceptable_reset
      :in_window -> :challenge_ack
      :out_of_window -> :silent_drop
    end
  end
end
