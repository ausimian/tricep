defmodule Tricep.Tcp.ChallengeAckLimiterTest do
  use ExUnit.Case, async: true

  alias Tricep.Tcp.ChallengeAckLimiter

  test "permits only the configured number of ACKs in a deterministic interval" do
    limiter = ChallengeAckLimiter.new(limit: 2, interval_ms: 100)

    assert {:allow, limiter} = ChallengeAckLimiter.allow(limiter, 1_000)
    assert {:allow, limiter} = ChallengeAckLimiter.allow(limiter, 1_050)
    assert {:limit, limiter} = ChallengeAckLimiter.allow(limiter, 1_099)
    assert limiter.sent == 2

    assert {:allow, limiter} = ChallengeAckLimiter.allow(limiter, 1_100)
    assert limiter.sent == 1
    assert limiter.window_started_at == 1_100
  end

  test "rejects non-positive and non-integer limiter configuration" do
    for opts <- [
          [limit: 0],
          [limit: -1],
          [limit: "2"],
          [interval_ms: 0],
          [interval_ms: -1],
          [interval_ms: "100"]
        ] do
      assert_raise ArgumentError, fn -> ChallengeAckLimiter.new(opts) end
    end

    assert ChallengeAckLimiter.valid_options?(%{})

    assert ChallengeAckLimiter.valid_options?(
             challenge_ack_limit: 2,
             challenge_ack_interval_ms: 100
           )

    refute ChallengeAckLimiter.valid_options?(challenge_ack_limit: 0)
    refute ChallengeAckLimiter.valid_options?(challenge_ack_limit: -1)
    refute ChallengeAckLimiter.valid_options?(challenge_ack_limit: "2")
    refute ChallengeAckLimiter.valid_options?(challenge_ack_interval_ms: 0)
    refute ChallengeAckLimiter.valid_options?(challenge_ack_interval_ms: -1)
    refute ChallengeAckLimiter.valid_options?(challenge_ack_interval_ms: "100")
  end
end
