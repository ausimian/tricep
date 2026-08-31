defmodule Tricep.Tcp.Closing do
  @moduledoc false

  alias Tricep.Socket
  alias Tricep.Tcp.Synchronized

  @initial_persist_timeout_ms 1_000

  def handle_event({:call, from}, {:send, _data, _timeout}, state_name, %Socket{})
      when state_name in [:fin_wait_1, :fin_wait_2, :closing, :last_ack, :time_wait] do
    {:keep_state_and_data, {:reply, from, {:error, :epipe}}}
  end

  def handle_event({:call, from}, {:recv, length, timeout}, :fin_wait_1, %Socket{} = state) do
    Socket.handle_recv_call(state, from, length, timeout)
  end

  def handle_event(
        {:timeout, timer_ref},
        {:recv_timeout, timer_ref},
        :fin_wait_1,
        %Socket{} = state
      ) do
    Socket.handle_recv_timeout(state, timer_ref)
  end

  def handle_event(:info, segment, :fin_wait_1, %Socket{} = state) when is_binary(segment) do
    case Synchronized.process(state.tcb, segment) do
      {:ok, parsed} -> Socket.handle_fin_wait_1_segment(state, parsed)
      outcome -> Socket.synchronized_rejection(state, outcome) |> transition()
    end
  end

  def handle_event({:call, from}, {:recv, length, timeout}, :fin_wait_2, %Socket{} = state) do
    Socket.handle_recv_call(state, from, length, timeout)
  end

  def handle_event(
        {:timeout, timer_ref},
        {:recv_timeout, timer_ref},
        :fin_wait_2,
        %Socket{} = state
      ) do
    Socket.handle_recv_timeout(state, timer_ref)
  end

  def handle_event({:timeout, :fin_wait_2}, :fin_wait_2_expired, :fin_wait_2, %Socket{} = state) do
    Socket.reset_connection(state, :etimedout, [{{:timeout, :fin_wait_2}, :cancel}])
    |> transition()
  end

  def handle_event(:info, segment, :fin_wait_2, %Socket{} = state) when is_binary(segment) do
    case Synchronized.process(state.tcb, segment, validate_ack?: true) do
      {:ok, parsed} ->
        Socket.handle_fin_wait_2_segment(state, parsed)

      outcome ->
        Socket.synchronized_rejection(
          state,
          outcome,
          {:connection, [{{:timeout, :fin_wait_2}, :cancel}]}
        )
        |> transition()
    end
  end

  def handle_event(
        {:call, from},
        {:recv, length, timeout},
        state_name,
        %Socket{read_shutdown: false, fin_received: true} = state
      )
      when state_name in [:closing, :last_ack, :time_wait] do
    Socket.handle_recv_call(state, from, length, timeout)
  end

  def handle_event({:timeout, :time_wait}, :time_wait_expired, :time_wait, %Socket{} = state) do
    Socket.reset_state(state)
    {:next_state, :closed, Socket.closed_data(state), {:change_callback_module, Socket}}
  end

  def handle_event(:info, segment, :time_wait, %Socket{} = state) when is_binary(segment) do
    case Tricep.Tcp.parse_segment(segment) do
      %{flags: flags, seq: sequence, payload: payload} ->
        Socket.handle_time_wait_segment(state, flags, sequence, byte_size(payload))

      _ ->
        :keep_state_and_data
    end
  end

  def handle_event(:info, segment, :closing, %Socket{} = state) when is_binary(segment) do
    case Synchronized.process(state.tcb, segment) do
      {:ok, parsed} -> Socket.handle_closing_segment(state, parsed)
      outcome -> Socket.synchronized_rejection(state, outcome, :close) |> transition()
    end
  end

  def handle_event(
        {:call, from},
        {:send, _data, _timeout},
        :close_wait,
        %Socket{write_shutdown: true}
      ) do
    {:keep_state_and_data, {:reply, from, {:error, :epipe}}}
  end

  def handle_event({:call, from}, {:send, data, timeout}, :close_wait, %Socket{} = state) do
    Socket.handle_send_call(state, from, data, timeout)
  end

  def handle_event(:internal, :flush_send_buffer, :close_wait, %Socket{} = state) do
    Socket.flush_send_buffer(state)
  end

  def handle_event(:internal, :send_pending_fin, :close_wait, %Socket{} = state) do
    Socket.send_pending_fin(state, :last_ack)
  end

  def handle_event(
        {:timeout, timer_ref},
        {:send_timeout, timer_ref},
        :close_wait,
        %Socket{} = state
      ) do
    Socket.handle_send_timeout(state, timer_ref)
  end

  def handle_event({:call, from}, {:recv, length, _timeout}, :close_wait, %Socket{} = state) do
    Socket.handle_final_recv_call(state, from, length)
  end

  def handle_event({:call, from}, :close, :close_wait, %Socket{write_shutdown: true} = state) do
    {:keep_state, state, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, :close, :close_wait, %Socket{} = state) do
    state
    |> Map.put(:read_shutdown, true)
    |> Socket.close_or_drain_send_buffer(from, :last_ack)
  end

  def handle_event(
        {:call, from},
        {:shutdown, :write},
        :close_wait,
        %Socket{write_shutdown: true} = state
      ) do
    {:keep_state, state, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, {:shutdown, :write}, :close_wait, %Socket{} = state) do
    Socket.close_or_drain_send_buffer(state, from, :last_ack)
  end

  def handle_event({:call, from}, {:shutdown, :read}, :close_wait, %Socket{} = state) do
    {:keep_state, %{state | read_shutdown: true}, {:reply, from, :ok}}
  end

  def handle_event(
        {:call, from},
        {:shutdown, :read_write},
        :close_wait,
        %Socket{write_shutdown: true} = state
      ) do
    {:keep_state, %{state | read_shutdown: true}, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, {:shutdown, :read_write}, :close_wait, %Socket{} = state) do
    state
    |> Map.put(:read_shutdown, true)
    |> Socket.close_or_drain_send_buffer(from, :last_ack)
  end

  def handle_event(:info, segment, :close_wait, %Socket{} = state) when is_binary(segment) do
    case Synchronized.process(state.tcb, segment) do
      {:ok, parsed} -> Socket.handle_close_wait_segment(state, parsed)
      outcome -> Socket.synchronized_rejection(state, outcome) |> transition()
    end
  end

  def handle_event(:info, segment, :last_ack, %Socket{} = state) when is_binary(segment) do
    case Synchronized.process(state.tcb, segment) do
      {:ok, parsed} -> Socket.handle_last_ack_segment(state, parsed) |> transition()
      outcome -> Socket.synchronized_rejection(state, outcome, :close) |> transition()
    end
  end

  def handle_event({:timeout, :rto}, :retransmit, state_name, %Socket{} = state)
      when state_name in [:close_wait, :fin_wait_1, :closing, :last_ack] do
    Socket.do_retransmit(state) |> transition()
  end

  def handle_event({:timeout, :persist}, :persist_probe, :fin_wait_1, %Socket{} = state) do
    new_state = %{
      state
      | persist_timer_active: false,
        persist_timeout_ms: @initial_persist_timeout_ms
    }

    {:keep_state, new_state, Socket.cancel_persist_timer_action(state)}
  end

  def handle_event({:timeout, :persist}, :persist_probe, :close_wait, %Socket{} = state) do
    Socket.handle_persist_probe(state)
  end

  use Tricep.Tcp.Socket.Callback

  defp transition({:next_state, :closed, state, actions}) do
    {:next_state, :closed, state, List.wrap(actions) ++ [{:change_callback_module, Socket}]}
  end

  defp transition(result), do: result
end
