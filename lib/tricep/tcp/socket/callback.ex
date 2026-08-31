defmodule Tricep.Tcp.Socket.Callback do
  @moduledoc false

  defmacro __using__(_opts) do
    quote do
      @behaviour :gen_statem

      alias Tricep.Socket

      @impl true
      def callback_mode, do: :handle_event_function

      @impl true
      def init(_args), do: {:stop, :invalid_callback_module}

      @impl true
      def terminate(reason, state_name, state_data),
        do: Socket.terminate(reason, state_name, state_data)

      @impl true
      def code_change(old_vsn, state_name, state_data, extra),
        do: Socket.code_change(old_vsn, state_name, state_data, extra)

      @impl true
      def format_status(status), do: Socket.format_status(status)

      @impl true
      def handle_event(
            :info,
            {:passive_handoff_prepare, owner, id},
            state_name,
            state_data
          )
          when is_pid(owner) and is_reference(id),
          do: Socket.handle_passive_handoff({:prepare, owner, id}, state_name, state_data)

      def handle_event(
            :info,
            {:passive_handoff_cancel, owner, id},
            state_name,
            state_data
          )
          when is_pid(owner) and is_reference(id),
          do: Socket.handle_passive_handoff({:cancel, owner, id}, state_name, state_data)

      def handle_event(
            :info,
            {:passive_handoff_claimed, owner, id},
            state_name,
            state_data
          )
          when is_pid(owner) and is_reference(id),
          do: Socket.handle_passive_handoff({:claimed, owner, id}, state_name, state_data)

      def handle_event(:info, {:icmpv6_error, event, quoted_tcp}, state_name, state_data) do
        Socket.handle_icmpv6_error_event(event, quoted_tcp, state_name, state_data)
      end

      def handle_event(
            :info,
            {:DOWN, monitor_ref, :process, _pid, _reason},
            state_name,
            %Socket{} = state_data
          ) do
        Socket.handle_process_down(state_name, state_data, monitor_ref)
      end

      def handle_event({:call, from}, :sockname, state_name, state_data) do
        Socket.handle_sockname(from, state_name, state_data)
      end

      # A cancelled named timer can already be queued when a callback module
      # transition occurs. State-specific handlers own live persist probes;
      # this catch-all absorbs the stale delivery in every active family.
      def handle_event({:timeout, :persist}, :persist_probe, _state_name, _state_data),
        do: :keep_state_and_data

      def handle_event({:timeout, :link_retry}, :link_retry, _state_name, _state_data),
        do: :keep_state_and_data

      def handle_event({:timeout, :link_retry}, {:retry, _path}, _state_name, _state_data),
        do: :keep_state_and_data

      def handle_event(:info, _message, _state_name, _state_data), do: :keep_state_and_data

      def handle_event({:call, from}, {:bind, _address}, _state_name, _state_data) do
        {:keep_state_and_data, {:reply, from, {:error, :einval}}}
      end

      def handle_event({:call, from}, {:listen, _backlog}, _state_name, _state_data) do
        {:keep_state_and_data, {:reply, from, {:error, :einval}}}
      end

      def handle_event({:call, from}, {:accept, _timeout}, _state_name, _state_data) do
        {:keep_state_and_data, {:reply, from, {:error, :einval}}}
      end

      def handle_event({:call, from}, {:connect, _address, _timeout}, _state_name, _state_data) do
        {:keep_state_and_data, {:reply, from, {:error, :eisconn}}}
      end

      def handle_event({:call, from}, {:send, _data, _timeout}, _state_name, _state_data) do
        {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
      end

      def handle_event({:call, from}, {:recv, _length, _timeout}, _state_name, _state_data) do
        {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
      end

      def handle_event({:call, from}, :close, _state_name, _state_data) do
        {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
      end

      def handle_event({:call, from}, {:shutdown, _how}, _state_name, _state_data) do
        {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
      end
    end
  end
end
