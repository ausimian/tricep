defmodule Tricep.Tcp.ChallengeAckLimiter do
  @moduledoc false

  # Each connection owns this small, pure limiter. RFC 5961 RST and SYN
  # challenge ACKs share its single budget; issue #124 owns policy for
  # non-RFC-5961 corrective ACKs. Callers supply time, which keeps the policy
  # deterministic in tests while the socket supplies monotonic time in
  # production.

  use TypedStruct

  @default_limit 10
  @default_interval_ms 5_000

  @type decision :: {:allow, t()} | {:limit, t()}

  typedstruct do
    field :limit, pos_integer(), default: @default_limit
    field :interval_ms, pos_integer(), default: @default_interval_ms
    field :window_started_at, integer() | nil, default: nil
    field :sent, non_neg_integer(), default: 0
  end

  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    limit = Keyword.get(opts, :limit, @default_limit)
    interval_ms = Keyword.get(opts, :interval_ms, @default_interval_ms)

    if positive_integer?(limit) and positive_integer?(interval_ms) do
      %__MODULE__{limit: limit, interval_ms: interval_ms}
    else
      raise ArgumentError, "challenge ACK limit and interval must be positive integers"
    end
  end

  @spec valid_options?(map() | keyword()) :: boolean()
  def valid_options?(opts) when is_map(opts) do
    valid_option?(Map.fetch(opts, :challenge_ack_limit)) and
      valid_option?(Map.fetch(opts, :challenge_ack_interval_ms))
  end

  def valid_options?(opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      valid_option?(Keyword.fetch(opts, :challenge_ack_limit)) and
        valid_option?(Keyword.fetch(opts, :challenge_ack_interval_ms))
    else
      false
    end
  end

  def valid_options?(_opts), do: false

  @spec allow(t(), integer()) :: decision()
  def allow(%__MODULE__{} = limiter, now) when is_integer(now) do
    limiter = reset_expired_window(limiter, now)

    if limiter.sent < limiter.limit do
      {:allow,
       %{limiter | window_started_at: limiter.window_started_at || now, sent: limiter.sent + 1}}
    else
      {:limit, limiter}
    end
  end

  defp reset_expired_window(%__MODULE__{window_started_at: nil} = limiter, _now), do: limiter

  defp reset_expired_window(%__MODULE__{} = limiter, now) do
    if now - limiter.window_started_at >= limiter.interval_ms do
      %{limiter | window_started_at: nil, sent: 0}
    else
      limiter
    end
  end

  defp valid_option?(:error), do: true
  defp valid_option?({:ok, value}), do: positive_integer?(value)

  defp positive_integer?(value), do: is_integer(value) and value > 0
end
