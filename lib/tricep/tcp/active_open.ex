defmodule Tricep.Tcp.ActiveOpen do
  @moduledoc false

  alias Tricep.Socket
  alias Tricep.Tcp
  alias Tricep.Tcp.Established
  alias Tricep.Tcp.Tcb

  @initial_rto_ms 1_000
  @max_retransmit_count 5

  def handle_event(:internal, {:send_syn, from, timeout}, :closed, %Socket{} = state) do
    iss = :crypto.strong_rand_bytes(4) |> :binary.decode_unsigned()
    syn_window = Socket.advertised_syn_window(state)

    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(state.pair, iss, 0, [:syn], syn_window,
        mss: state.tcb.rcv_mss,
        window_scale: state.tcb.rcv_wnd_scale
      )

    packet = Tricep.Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment)
    _ = Tricep.Link.send(state.link, packet)

    base_state = %{
      state
      | tcb: Tcb.begin_active_open(state.tcb, iss, syn_window),
        syn_retransmit_count: 0,
        rto_ms: @initial_rto_ms,
        soft_error: nil
    }

    case timeout do
      :nowait ->
        ref = make_ref()
        {caller_pid, _} = from
        new_state = %{base_state | connect_selects: [{caller_pid, ref}]}

        {:next_state, {:syn_sent, :nowait}, new_state,
         [
           {{:timeout, :rto}, @initial_rto_ms, :syn_timeout_nowait},
           {:reply, from, {:select, {:select_info, :connect, ref}}}
         ]}

      :infinity ->
        {:next_state, {:syn_sent, from}, base_state,
         {{:timeout, :rto}, @initial_rto_ms, {:syn_timeout, from}}}

      ms when is_integer(ms) ->
        {:next_state, {:syn_sent, from}, base_state,
         [
           {{:timeout, :rto}, @initial_rto_ms, {:syn_timeout, from}},
           {{:timeout, :connect_timeout}, ms, {:connect_timeout, from}}
         ]}
    end
  end

  def handle_event(:info, segment, {:syn_sent, from}, %Socket{} = state)
      when is_tuple(from) and is_binary(segment) do
    case Socket.syn_sent_segment(state, segment) do
      :reset ->
        Socket.reset_state(state)

        {:next_state, :closed, Socket.closed_data(state),
         [
           {{:timeout, :rto}, :cancel},
           {{:timeout, :link_retry}, :cancel},
           {{:timeout, :connect_timeout}, :cancel},
           {:reply, from, {:error, :econnrefused}},
           {:change_callback_module, Socket}
         ]}

      {:established, new_state} ->
        new_state = Socket.complete_link_retry(new_state)
        Socket.send_ack(new_state.tcb.rcv_nxt, new_state)

        {:next_state, :established, new_state,
         [
           {{:timeout, :rto}, :cancel},
           {{:timeout, :link_retry}, :cancel},
           {{:timeout, :connect_timeout}, :cancel},
           {:reply, from, :ok},
           {:change_callback_module, Established}
         ]}

      {:bad_ack, acknowledgment} ->
        Socket.send_rst(acknowledgment, state)
        :keep_state_and_data

      :ignore ->
        :keep_state_and_data
    end
  end

  def handle_event(:info, segment, {:syn_sent, :nowait}, %Socket{} = state)
      when is_binary(segment) do
    case Socket.syn_sent_segment(state, segment) do
      :reset ->
        {state_name, state_data} = Socket.nowait_connect_failure(state, :econnrefused)

        {:next_state, state_name, state_data,
         [
           {{:timeout, :rto}, :cancel},
           {{:timeout, :link_retry}, :cancel},
           {:change_callback_module, Socket}
         ]}

      {:established, new_state} ->
        new_state = Socket.complete_link_retry(new_state)
        Socket.notify_selects(state.connect_selects)
        Socket.send_ack(new_state.tcb.rcv_nxt, new_state)

        {:next_state, :established, new_state,
         [
           {{:timeout, :rto}, :cancel},
           {{:timeout, :link_retry}, :cancel},
           {:change_callback_module, Established}
         ]}

      {:bad_ack, acknowledgment} ->
        Socket.send_rst(acknowledgment, state)
        :keep_state_and_data

      :ignore ->
        :keep_state_and_data
    end
  end

  def handle_event(:info, :send_syn_ack, :syn_received, %Socket{} = state) do
    Socket.send_syn_ack(state)
    {:keep_state, state, {{:timeout, :rto}, @initial_rto_ms, :syn_ack_timeout}}
  end

  def handle_event(:info, segment, :syn_received, %Socket{} = state) when is_binary(segment) do
    case Socket.syn_received_segment(state, segment) do
      :acceptable_reset ->
        Socket.reset_state(state)
        Socket.notify_passive_owner(state, :passive_failed)
        {:stop, :normal}

      :challenge_ack ->
        Socket.send_challenge_ack(state)

      :silent_drop ->
        :keep_state_and_data

      :unacceptable_segment ->
        Socket.reject_unacceptable_segment(state)

      {:established, next_state, new_state, receive_actions} ->
        new_state = Socket.complete_link_retry(new_state)
        Socket.notify_passive_owner(state, :passive_established)

        {:next_state, next_state, new_state,
         receive_actions ++
           [
             {{:timeout, :rto}, :cancel},
             {{:timeout, :link_retry}, :cancel},
             {:change_callback_module, callback_module(next_state)}
           ]}

      {:bad_ack, acknowledgment} ->
        Socket.send_rst(acknowledgment, state)
        :keep_state_and_data

      :retransmit_syn_ack ->
        Socket.send_syn_ack(state)
        :keep_state_and_data

      :ignore ->
        :keep_state_and_data
    end
  end

  def handle_event({:timeout, :rto}, :syn_ack_timeout, :syn_received, %Socket{} = state) do
    if state.syn_retransmit_count >= @max_retransmit_count do
      reason = Socket.retry_exhaustion_error(state)
      Socket.reset_state(state)
      Socket.notify_passive_owner(state, {:passive_failed, reason})
      {:stop, :normal}
    else
      case Socket.retransmit_syn_ack(state) do
        {:link_stall_exhausted, state, reason} ->
          Socket.reset_state(state)
          Socket.notify_passive_owner(state, {:passive_failed, reason})
          {:stop, :normal}

        result ->
          result
      end
    end
  end

  def handle_event(
        {:timeout, :link_retry},
        {:retry, :syn_ack},
        :syn_received,
        %Socket{} = state
      ) do
    if state.syn_retransmit_count >= @max_retransmit_count do
      reason = Socket.retry_exhaustion_error(state)
      Socket.reset_state(state)
      Socket.notify_passive_owner(state, {:passive_failed, reason})
      {:stop, :normal}
    else
      case Socket.retry_link_syn_ack(state) do
        {:link_stall_exhausted, state, reason} ->
          Socket.reset_state(state)
          Socket.notify_passive_owner(state, {:passive_failed, reason})
          {:stop, :normal}

        result ->
          result
      end
    end
  end

  def handle_event({:timeout, :rto}, {:syn_timeout, from}, {:syn_sent, from}, %Socket{} = state) do
    if state.syn_retransmit_count >= @max_retransmit_count do
      Socket.reset_state(state)

      {:next_state, :closed, Socket.closed_data(state),
       [
         {{:timeout, :connect_timeout}, :cancel},
         {:reply, from, {:error, Socket.retry_exhaustion_error(state)}},
         {:change_callback_module, Socket}
       ]}
    else
      case Socket.retransmit_syn(state, {:syn_timeout, from}) do
        {:link_stall_exhausted, state, reason} ->
          Socket.reset_state(state)

          {:next_state, :closed, Socket.closed_data(state),
           [
             {{:timeout, :connect_timeout}, :cancel},
             {:reply, from, {:error, reason}},
             {:change_callback_module, Socket}
           ]}

        result ->
          result
      end
    end
  end

  def handle_event(
        {:timeout, :link_retry},
        {:retry, {:syn, {:syn_timeout, from}}},
        {:syn_sent, from},
        %Socket{} = state
      ) do
    if state.syn_retransmit_count >= @max_retransmit_count do
      Socket.reset_state(state)

      {:next_state, :closed, Socket.closed_data(state),
       [
         {{:timeout, :connect_timeout}, :cancel},
         {:reply, from, {:error, Socket.retry_exhaustion_error(state)}},
         {:change_callback_module, Socket}
       ]}
    else
      case Socket.retry_link_syn(state, {:syn_timeout, from}) do
        {:link_stall_exhausted, state, reason} ->
          Socket.reset_state(state)

          {:next_state, :closed, Socket.closed_data(state),
           [
             {{:timeout, :connect_timeout}, :cancel},
             {:reply, from, {:error, reason}},
             {:change_callback_module, Socket}
           ]}

        result ->
          result
      end
    end
  end

  def handle_event(
        {:timeout, :rto},
        :syn_timeout_nowait,
        {:syn_sent, :nowait},
        %Socket{} = state
      ) do
    if state.syn_retransmit_count >= @max_retransmit_count do
      {state_name, state_data} =
        Socket.nowait_connect_failure(state, Socket.retry_exhaustion_error(state))

      {:next_state, state_name, state_data, {:change_callback_module, Socket}}
    else
      case Socket.retransmit_syn(state, :syn_timeout_nowait) do
        {:link_stall_exhausted, state, reason} ->
          {state_name, state_data} = Socket.nowait_connect_failure(state, reason)
          {:next_state, state_name, state_data, {:change_callback_module, Socket}}

        result ->
          result
      end
    end
  end

  def handle_event(
        {:timeout, :link_retry},
        {:retry, {:syn, :syn_timeout_nowait}},
        {:syn_sent, :nowait},
        %Socket{} = state
      ) do
    if state.syn_retransmit_count >= @max_retransmit_count do
      {state_name, state_data} =
        Socket.nowait_connect_failure(state, Socket.retry_exhaustion_error(state))

      {:next_state, state_name, state_data, {:change_callback_module, Socket}}
    else
      case Socket.retry_link_syn(state, :syn_timeout_nowait) do
        {:link_stall_exhausted, state, reason} ->
          {state_name, state_data} = Socket.nowait_connect_failure(state, reason)
          {:next_state, state_name, state_data, {:change_callback_module, Socket}}

        result ->
          result
      end
    end
  end

  def handle_event(
        {:timeout, :connect_timeout},
        {:connect_timeout, from},
        {:syn_sent, from},
        %Socket{} = state
      ) do
    Socket.reset_state(state)

    {:next_state, :closed, Socket.closed_data(state),
     [
       {{:timeout, :rto}, :cancel},
       {{:timeout, :link_retry}, :cancel},
       {:reply, from, {:error, :timeout}},
       {:change_callback_module, Socket}
     ]}
  end

  def handle_event(
        {:call, {caller_pid, _} = from},
        {:connect, _address, :nowait},
        {:syn_sent, :nowait},
        %Socket{} = state
      ) do
    ref = make_ref()
    new_state = %{state | connect_selects: state.connect_selects ++ [{caller_pid, ref}]}
    {:keep_state, new_state, {:reply, from, {:select, {:select_info, :connect, ref}}}}
  end

  def handle_event({:call, from}, {:send, _data, _timeout}, {:syn_sent, _}, %Socket{}) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  def handle_event({:call, from}, {:recv, _length, _timeout}, {:syn_sent, _}, %Socket{}) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  def handle_event({:call, from}, :close, {:syn_sent, _}, %Socket{}) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  def handle_event({:call, from}, {:shutdown, _how}, {:syn_sent, _}, %Socket{}) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  use Tricep.Tcp.Socket.Callback

  defp callback_module(:established), do: Established

  defp callback_module(state_name) when state_name in [:close_wait, :fin_wait_1, :fin_wait_2],
    do: Tricep.Tcp.Closing
end
