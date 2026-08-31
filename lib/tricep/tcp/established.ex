defmodule Tricep.Tcp.Established do
  @moduledoc false

  alias Tricep.Socket
  alias Tricep.Tcp.Synchronized

  def handle_event(
        {:call, from},
        {:connect, _address, _timeout},
        :established,
        %Socket{} = state
      ) do
    case Socket.take_select_for_pid(state.connect_selects, elem(from, 0)) do
      {{caller_pid, _ref}, remaining_selects} when caller_pid == elem(from, 0) ->
        {:keep_state, %{state | connect_selects: remaining_selects}, {:reply, from, :ok}}

      nil ->
        {:keep_state_and_data, {:reply, from, {:error, :eisconn}}}
    end
  end

  def handle_event(
        {:call, from},
        {:send, _data, _timeout},
        :established,
        %Socket{write_shutdown: true}
      ) do
    {:keep_state_and_data, {:reply, from, {:error, :epipe}}}
  end

  def handle_event({:call, from}, {:send, data, timeout}, :established, %Socket{} = state) do
    Socket.handle_send_call(state, from, data, timeout)
  end

  def handle_event(
        {:timeout, timer_ref},
        {:send_timeout, timer_ref},
        :established,
        %Socket{} = state
      ) do
    Socket.handle_send_timeout(state, timer_ref)
  end

  def handle_event(:internal, :flush_send_buffer, :established, %Socket{} = state) do
    Socket.flush_send_buffer(state)
  end

  def handle_event(:internal, :send_pending_fin, :established, %Socket{} = state) do
    Socket.send_pending_fin(state, :fin_wait_1) |> transition()
  end

  def handle_event({:call, from}, {:recv, length, timeout}, :established, %Socket{} = state) do
    Socket.handle_recv_call(state, from, length, timeout)
  end

  def handle_event(
        {:timeout, timer_ref},
        {:recv_timeout, timer_ref},
        :established,
        %Socket{} = state
      ) do
    Socket.handle_recv_timeout(state, timer_ref)
  end

  def handle_event(:info, segment, :established, %Socket{} = state) when is_binary(segment) do
    case Synchronized.process(state.tcb, segment, validate_ack?: true) do
      {:ok, parsed} -> Socket.handle_established_segment(state, parsed) |> transition()
      outcome -> Socket.synchronized_rejection(state, outcome) |> transition()
    end
  end

  def handle_event({:timeout, :rto}, :retransmit, :established, %Socket{} = state) do
    Socket.do_retransmit(state) |> transition()
  end

  def handle_event({:timeout, :persist}, :persist_probe, :established, %Socket{} = state) do
    Socket.handle_persist_probe(state)
  end

  def handle_event({:call, from}, :close, :established, %Socket{write_shutdown: true} = state) do
    {:keep_state, state, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, :close, :established, %Socket{} = state) do
    state
    |> Map.put(:read_shutdown, true)
    |> Socket.close_or_drain_send_buffer(from, :fin_wait_1)
    |> transition()
  end

  def handle_event(
        {:call, from},
        {:shutdown, :write},
        :established,
        %Socket{write_shutdown: true} = state
      ) do
    {:keep_state, state, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, {:shutdown, :write}, :established, %Socket{} = state) do
    Socket.close_or_drain_send_buffer(state, from, :fin_wait_1) |> transition()
  end

  def handle_event({:call, from}, {:shutdown, :read}, :established, %Socket{} = state) do
    {:keep_state, %{state | read_shutdown: true}, {:reply, from, :ok}}
  end

  def handle_event(
        {:call, from},
        {:shutdown, :read_write},
        :established,
        %Socket{write_shutdown: true} = state
      ) do
    {:keep_state, %{state | read_shutdown: true}, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, {:shutdown, :read_write}, :established, %Socket{} = state) do
    state
    |> Map.put(:read_shutdown, true)
    |> Socket.close_or_drain_send_buffer(from, :fin_wait_1)
    |> transition()
  end

  use Tricep.Tcp.Socket.Callback

  defp transition({:next_state, state_name, state, actions})
       when state_name in [:close_wait, :fin_wait_1] do
    {:next_state, state_name, state,
     List.wrap(actions) ++ [{:change_callback_module, Tricep.Tcp.Closing}]}
  end

  defp transition({:next_state, :closed, state, actions}) do
    {:next_state, :closed, state, List.wrap(actions) ++ [{:change_callback_module, Socket}]}
  end

  defp transition(result), do: result
end
