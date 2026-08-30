defmodule Tricep.Tcp.ConnectionSupervisor do
  @moduledoc false

  use GenServer
  use TypedStruct

  alias Tricep.Socket

  defmodule Child do
    @moduledoc false

    use TypedStruct

    typedstruct enforce: true do
      field :status, :pending | :queued
    end
  end

  typedstruct enforce: true do
    field :listener, pid()
    field :listener_monitor, reference()
    field :children, %{optional(pid()) => Child.t()}, default: %{}
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

  @doc """
  Atomically releases an established child from listener supervision to a live
  accept caller.

  A claim succeeds once. Repeating a completed claim is side-effect free and
  returns `{:error, :not_queued}`; `{:error, :caller_down}` leaves the child
  queued, while `{:error, :closed}` means the supervisor could not receive the
  claim. Issue #131 will build the ownership-transfer handshake on this single
  authority without changing the listener's public API in the meantime.
  """
  @spec claim(pid(), pid(), pid()) :: :ok | {:error, :caller_down | :not_queued | :closed}
  def claim(server, child, caller) when is_pid(server) and is_pid(child) and is_pid(caller) do
    GenServer.call(server, {:claim, child, caller}, :infinity)
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

  def handle_call({:claim, child, caller}, _from, state) do
    case Map.pop(state.children, child) do
      {%Child{status: :queued}, children} ->
        if Process.alive?(caller) do
          Process.unlink(child)
          {:reply, :ok, %{state | children: children}}
        else
          {:reply, {:error, :caller_down}, state}
        end

      {_child, _children} ->
        {:reply, {:error, :not_queued}, state}
    end
  end

  def handle_call(:close, _from, state) do
    {:stop, :normal, :ok, state}
  end

  @impl true
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

  def handle_info({:EXIT, child, _reason}, state) when is_pid(child) do
    {:noreply, report_failed_child(state, child, nil)}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    Enum.each(state.children, fn {child, _entry} ->
      Process.unlink(child)
      Process.exit(child, :shutdown)
    end)

    :ok
  end

  defp report_failed_child(state, child, reason) do
    case Map.pop(state.children, child) do
      {%Child{}, children} ->
        if is_nil(reason) do
          send(state.listener, {:passive_failed, child})
        else
          send(state.listener, {:passive_failed, child, reason})
        end

        %{state | children: children}

      {nil, _children} ->
        state
    end
  end
end
