defmodule Tricep.Tcp.ConnectionSupervisor do
  @moduledoc false

  use GenServer
  use TypedStruct

  alias Tricep.Socket

  require Logger

  # The claim is map-only and normally returns in a scheduler turn. A finite
  # bound keeps an accept retry from wedging the listener if its supervisor is
  # already stalled; broader controlling-process/cancellation semantics remain
  # tracked by #109.
  @claim_timeout 50

  defmodule Child do
    @moduledoc false

    use TypedStruct

    typedstruct enforce: true do
      field :status,
            :pending
            | :queued
            | {:handoff, reference()}
            | {:claimed, reference()}
    end
  end

  defmodule Handoff do
    @moduledoc false

    use TypedStruct

    typedstruct enforce: true do
      field :id, reference()
      field :child, pid()
      field :caller, pid()
      field :caller_monitor, reference() | nil
    end
  end

  typedstruct enforce: true do
    field :listener, pid()
    field :listener_monitor, reference()
    field :children, %{optional(pid()) => Child.t()}, default: %{}
    field :handoffs, %{optional(reference()) => Handoff.t()}, default: %{}
  end

  @spec start(pid()) :: GenServer.on_start()
  def start(listener) when is_pid(listener) do
    GenServer.start(__MODULE__, listener)
  end

  @spec start_child(pid(), map()) :: {:ok, pid()} | {:error, term()}
  def start_child(server, opts) when is_pid(server) and is_map(opts) do
    GenServer.call(server, {:start_child, opts}, :infinity)
  catch
    :exit, {_reason, {GenServer, :call, [^server | _]}} -> {:error, :closed}
  end

  @doc false
  @spec begin_handoff(pid(), reference(), pid(), pid()) :: :ok
  def begin_handoff(server, id, child, caller)
      when is_pid(server) and is_reference(id) and is_pid(child) and is_pid(caller) do
    send(server, {:begin_handoff, self(), id, child, caller})
    :ok
  end

  @doc false
  @spec cancel_handoff(pid(), reference(), atom()) :: :ok
  def cancel_handoff(server, id, reason)
      when is_pid(server) and is_reference(id) and is_atom(reason) do
    send(server, {:cancel_handoff, self(), id, reason})
    :ok
  end

  @doc false
  @spec discard_claimed(pid(), reference(), pid()) :: :ok
  def discard_claimed(server, id, child)
      when is_pid(server) and is_reference(id) and is_pid(child) do
    send(server, {:discard_claimed, self(), id, child})
    :ok
  end

  @doc false
  @spec claim_child(pid(), reference(), pid(), pid()) ::
          :ok | {:error, :stale | :caller_down | :closed}
  def claim_child(server, id, child, caller)
      when is_pid(server) and is_reference(id) and is_pid(child) and is_pid(caller) do
    GenServer.call(server, {:claim_child, id, child, caller}, @claim_timeout)
  catch
    :exit, {_reason, {GenServer, :call, [^server | _]}} -> {:error, :closed}
  end

  @spec close(pid()) :: :ok | {:error, :closed}
  def close(server) when is_pid(server) do
    GenServer.call(server, :close, :infinity)
  catch
    :exit, {_reason, {GenServer, :call, [^server | _]}} -> {:error, :closed}
  end

  @impl true
  def init(listener) do
    # Passive children are linked so even an untrappable supervisor failure
    # reaps every unclaimed TCP incarnation. Trap their exits so a failed child
    # is reported to the listener instead of taking its siblings down.
    Process.flag(:trap_exit, true)
    {:ok, %__MODULE__{listener: listener, listener_monitor: Process.monitor(listener)}}
  end

  @impl true
  def handle_call({:start_child, opts}, _from, state) do
    opts = Map.put(opts, :passive_owner, self())

    case Socket.start_passive_connection(opts) do
      {:ok, child} ->
        Process.link(child)
        send(child, :send_syn_ack)

        children = Map.put(state.children, child, %Child{status: :pending})
        {:reply, {:ok, child}, %{state | children: children}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}

      :ignore ->
        {:reply, {:error, :ignored}, state}

      other ->
        {:reply, {:error, {:unexpected_start_result, other}}, state}
    end
  end

  def handle_call(:close, _from, state) do
    {:stop, :normal, :ok, state}
  end

  # This is intentionally the only synchronous operation in the passive
  # handoff path. It touches supervisor-local maps and links only: never a
  # peer-fed child mailbox. The listener calls it after the asynchronous
  # prepare acknowledgement has made the child claimable.
  def handle_call({:claim_child, id, child, caller}, _from, state) do
    case Map.get(state.children, child) do
      %Child{status: {:claimed, ^id}} when is_pid(caller) ->
        if Process.alive?(caller) do
          # Clearing the child's passive marker is best-effort bookkeeping
          # after the supervisor-local ownership decision. It is neither
          # awaited nor part of accept linearization.
          send(child, {:passive_handoff_claimed, self(), id})
          Process.unlink(child)
          # The caller can still exit after this liveness check but before it
          # observes the reply. Transferring that controlling-process window
          # is deliberately out of #131's passive lifecycle scope (#109).
          {:reply, :ok, %{state | children: Map.delete(state.children, child)}}
        else
          {:reply, {:error, :caller_down}, state}
        end

      _ ->
        {:reply, {:error, :stale}, state}
    end
  end

  @impl true
  def handle_info({:begin_handoff, listener, id, child, caller}, state)
      when listener == state.listener do
    {:noreply, start_handoff(state, listener, id, child, caller)}
  end

  def handle_info({:passive_handoff_prepared, child, owner, id}, state) when owner == self() do
    {:noreply, mark_handoff_prepared(state, child, id)}
  end

  def handle_info({:passive_handoff_rejected, child, owner, id}, state) when owner == self() do
    {:noreply, reject_handoff(state, child, id)}
  end

  def handle_info({:cancel_handoff, listener, id, reason}, state)
      when listener == state.listener do
    {:noreply, cancel_active_handoff(state, id, reason)}
  end

  def handle_info({:discard_claimed, listener, id, child}, state)
      when listener == state.listener do
    {:noreply, discard_claimed_child(state, id, child)}
  end

  def handle_info({:passive_established, child}, state) do
    case Map.get(state.children, child) do
      %Child{status: :pending} = entry ->
        children = Map.put(state.children, child, %{entry | status: :queued})
        send(state.listener, {:passive_established, child})
        {:noreply, %{state | children: children}}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:passive_failed, child}, state) do
    {:noreply, report_failed_child(state, child, nil)}
  end

  def handle_info({:passive_failed, child, reason}, state) do
    {:noreply, report_failed_child(state, child, reason)}
  end

  def handle_info({:DOWN, monitor, :process, listener, _reason}, state)
      when monitor == state.listener_monitor and listener == state.listener do
    {:stop, :normal, state}
  end

  def handle_info({:DOWN, monitor, :process, _caller, _reason}, state) do
    case handoff_id_by_caller_monitor(state, monitor) do
      nil -> {:noreply, state}
      id -> {:noreply, cancel_active_handoff(state, id, :caller_down)}
    end
  end

  def handle_info({:EXIT, child, _reason}, state) when is_pid(child) do
    {:noreply, report_failed_child(state, child, nil)}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    Enum.each(state.handoffs, fn {_id, handoff} ->
      release_handoff_monitor(handoff)
    end)

    Enum.each(state.children, fn {child, _entry} ->
      Process.unlink(child)
      Process.exit(child, :shutdown)
    end)

    :ok
  end

  defp start_handoff(state, listener, id, child, caller) do
    case {listener == state.listener, Map.get(state.handoffs, id), Map.get(state.children, child)} do
      {true, nil, %Child{status: :queued} = entry} when is_pid(caller) ->
        if Process.alive?(caller) do
          handoff = %Handoff{
            id: id,
            child: child,
            caller: caller,
            caller_monitor: Process.monitor(caller)
          }

          send(child, {:passive_handoff_prepare, self(), id})

          %{
            state
            | children: Map.put(state.children, child, %{entry | status: {:handoff, id}}),
              handoffs: Map.put(state.handoffs, id, handoff)
          }
        else
          # The child remains linked and queued here. Tell the listener to
          # restore its local queue entry instead of reporting a failure that
          # would make the two ownership registries diverge.
          send(listener, {:passive_handoff_cancelled, self(), id, child, :caller_down})
          state
        end

      _ ->
        send(listener, {:passive_handoff_failed, self(), id, child, :stale})
        state
    end
  end

  defp mark_handoff_prepared(state, child, id) do
    case Map.get(state.handoffs, id) do
      %Handoff{child: ^child} = handoff ->
        if Process.alive?(handoff.caller) and Process.alive?(state.listener) do
          # The child has synchronised with its peer-fed mailbox. It remains
          # linked here until a later local claim atomically transfers it to
          # an accept caller; no listener callback waits on the child.
          release_handoff_monitor(handoff)
          send(state.listener, {:passive_handoff_ready, self(), id, child})

          %{
            state
            | children: Map.put(state.children, child, %Child{status: {:claimed, id}}),
              handoffs: Map.delete(state.handoffs, id)
          }
        else
          cancel_active_handoff(state, id, :caller_down)
        end

      _ ->
        # The listener cancelled this token before a suspended child processed
        # its prepare message. Keep ownership intact and discard the late ack.
        send(child, {:passive_handoff_cancel, self(), id})
        state
    end
  end

  defp reject_handoff(state, child, id) do
    case Map.get(state.handoffs, id) do
      %Handoff{child: ^child} = handoff ->
        Logger.warning("TCP passive handoff prepare was rejected; reaping child")
        release_handoff_monitor(handoff)
        reap_handoff_child(child)

        send(state.listener, {:passive_handoff_failed, self(), id, child, :stale})

        %{
          state
          | children: Map.delete(state.children, child),
            handoffs: Map.delete(state.handoffs, id)
        }

      _ ->
        state
    end
  end

  defp cancel_active_handoff(state, id, reason) do
    case Map.get(state.handoffs, id) do
      %Handoff{child: child} = handoff ->
        handoffs = Map.delete(state.handoffs, id)
        release_handoff_monitor(handoff)
        send(child, {:passive_handoff_cancel, self(), id})

        case Map.get(state.children, child) do
          %Child{status: {:handoff, ^id}} = entry ->
            children = Map.put(state.children, child, %{entry | status: :queued})
            send(state.listener, {:passive_handoff_cancelled, self(), id, child, reason})
            %{state | children: children, handoffs: handoffs}

          _ ->
            Logger.warning("TCP passive handoff cancellation lost its child")
            send(state.listener, {:passive_handoff_failed, self(), id, child, :stale})
            %{state | handoffs: handoffs}
        end

      nil ->
        state
    end
  end

  defp discard_claimed_child(state, id, child) do
    case Map.get(state.children, child) do
      %Child{status: {:claimed, ^id}} ->
        Logger.warning("TCP passive handoff was settled before local claim; reaping child")
        reap_handoff_child(child)
        %{state | children: Map.delete(state.children, child)}

      _ ->
        state
    end
  end

  defp report_failed_child(state, child, reason) do
    case Map.pop(state.children, child) do
      {%Child{status: {:handoff, id}}, children} ->
        state = %{state | children: children}
        fail_handoff(state, id, child, reason)

      {%Child{}, children} ->
        notify_failed_child(state.listener, child, reason)
        %{state | children: children}

      {nil, _children} ->
        state
    end
  end

  defp fail_handoff(state, id, child, reason) do
    case Map.pop(state.handoffs, id) do
      {%Handoff{} = handoff, handoffs} ->
        release_handoff_monitor(handoff)
        send(state.listener, {:passive_handoff_failed, self(), id, child, reason || :stale})
        %{state | handoffs: handoffs}

      {nil, _handoffs} ->
        state
    end
  end

  defp notify_failed_child(listener, child, nil), do: send(listener, {:passive_failed, child})

  defp notify_failed_child(listener, child, reason),
    do: send(listener, {:passive_failed, child, reason})

  defp handoff_id_by_caller_monitor(state, monitor) do
    Enum.find_value(state.handoffs, fn {id, handoff} ->
      if handoff.caller_monitor == monitor, do: id
    end)
  end

  defp release_handoff_monitor(%Handoff{caller_monitor: nil}), do: :ok

  defp release_handoff_monitor(%Handoff{caller_monitor: monitor}) do
    Process.demonitor(monitor, [:flush])
    :ok
  end

  defp reap_handoff_child(child) do
    if Process.alive?(child) do
      Process.unlink(child)
      Process.exit(child, :shutdown)
    end

    :ok
  end
end
