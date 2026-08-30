defmodule Tricep.Tcp.Listener do
  @moduledoc false

  use TypedStruct

  alias Tricep.Address
  alias Tricep.Application
  alias Tricep.Tcp.ConnectionSupervisor

  require Logger

  defmodule Child do
    @moduledoc false

    use TypedStruct

    typedstruct enforce: true do
      field :status, :pending | :queued
    end
  end

  defmodule Accepted do
    @moduledoc false

    use TypedStruct

    typedstruct enforce: true do
      field :child, pid()
    end
  end

  defmodule Waiter do
    @moduledoc false

    use TypedStruct

    typedstruct enforce: true do
      field :from, term()
      field :id, reference()
      field :timer, reference() | nil
      field :monitor, reference()
    end
  end

  typedstruct enforce: true do
    field :local_addr, binary()
    field :local_port, non_neg_integer()
    field :socket_opts, map() | keyword()
    field :backlog, pos_integer()
    field :connection_supervisor, pid()
    field :connection_supervisor_monitor, reference()
    field :passive_start_failures, non_neg_integer(), default: 0
    field :pending_count, non_neg_integer(), default: 0
    field :accept_queue, [Accepted.t()], default: []
    field :accept_waiters, [Waiter.t()], default: []
    field :accept_selects, list(), default: []
    field :children, %{optional(pid()) => Child.t()}, default: %{}
  end

  @spec new(pid(), map(), pos_integer()) :: {:ok, t()} | {:error, atom()}
  def new(
        listener,
        %{local_addr: local_addr, local_port: local_port, socket_opts: socket_opts},
        backlog
      )
      when is_pid(listener) and is_integer(backlog) and backlog > 0 do
    case ConnectionSupervisor.start(listener) do
      {:ok, connection_supervisor} ->
        register_listener(
          connection_supervisor,
          local_addr,
          local_port,
          socket_opts,
          backlog
        )

      {:error, {:already_started, _pid}} ->
        {:error, :ealready}

      {:error, reason} when is_atom(reason) ->
        {:error, reason}

      {:error, _reason} ->
        {:error, :enomem}

      :ignore ->
        {:error, :enomem}

      _other ->
        {:error, :enomem}
    end
  end

  defp register_listener(connection_supervisor, local_addr, local_port, socket_opts, backlog) do
    case Application.register_listener(local_addr, local_port) do
      :ok ->
        {:ok,
         %__MODULE__{
           local_addr: local_addr,
           local_port: local_port,
           socket_opts: socket_opts,
           backlog: backlog,
           connection_supervisor: connection_supervisor,
           connection_supervisor_monitor: Process.monitor(connection_supervisor)
         }}

      {:error, {:already_registered, _pid}} ->
        ConnectionSupervisor.close(connection_supervisor)
        {:error, :eaddrinuse}

      _other ->
        ConnectionSupervisor.close(connection_supervisor)
        {:error, :enomem}
    end
  end

  @spec handle_event(term(), term(), t()) :: term()
  def handle_event({:call, from}, {:listen, backlog}, state)
      when is_integer(backlog) and backlog > 0 do
    {:keep_state, %{state | backlog: backlog}, {:reply, from, :ok}}
  end

  def handle_event({:call, from}, {:accept, timeout}, state) do
    {caller, _tag} = from

    case take_accepted_child(state, caller) do
      {:ok, child, state} ->
        if Process.alive?(caller) do
          {:keep_state, state, {:reply, from, {:ok, child}}}
        else
          # This is the same handoff race handled for queued waiters below.
          # A dead direct caller cannot receive a reply, so reaping is safer
          # than leaving the child outside the supervisor failure domain.
          Process.exit(child, :shutdown)
          {:keep_state, state}
        end

      {:empty, state} ->
        wait_for_accept(state, from, timeout)

      {:closed, state} ->
        {:keep_state, state, {:reply, from, {:error, :closed}}}

      {:caller_down, state} ->
        {:keep_state, state, {:reply, from, {:error, :closed}}}
    end
  end

  def handle_event(:internal, {:wait_accept, from, :nowait}, state) do
    ref = make_ref()
    {caller, _tag} = from
    select = {caller, ref}

    {:keep_state, %{state | accept_selects: state.accept_selects ++ [select]},
     {:reply, from, {:select, {:select_info, :accept, ref}}}}
  end

  def handle_event(:internal, {:wait_accept, from, :infinity}, state) do
    waiter = new_waiter(from, make_ref(), nil)
    {:keep_state, %{state | accept_waiters: state.accept_waiters ++ [waiter]}}
  end

  def handle_event(:internal, {:wait_accept, from, timeout}, state)
      when is_integer(timeout) and timeout >= 0 do
    id = make_ref()
    timer = make_ref()
    waiter = new_waiter(from, id, timer)

    {:keep_state, %{state | accept_waiters: state.accept_waiters ++ [waiter]},
     {{:timeout, timer}, timeout, {:accept_timeout, id}}}
  end

  def handle_event(:internal, {:wait_accept, from, _timeout}, _state) do
    {:keep_state_and_data, {:reply, from, {:error, :einval}}}
  end

  def handle_event({:timeout, timer}, {:accept_timeout, id}, state) do
    case take_waiter_by_id(state, id) do
      {:ok, %Waiter{timer: ^timer} = waiter, state} ->
        release_waiter_monitor(waiter)
        {:keep_state, state, {:reply, waiter.from, {:error, :timeout}}}

      _other ->
        :keep_state_and_data
    end
  end

  def handle_event(:info, {:passive_syn, src_addr, dst_addr, src_port, dst_port, segment}, state) do
    case passive_connection_opts(state, src_addr, dst_addr, src_port, dst_port, segment) do
      {:ok, opts} -> start_passive_child(state, opts)
      :ignore -> :keep_state_and_data
    end
  end

  def handle_event(:info, {:passive_established, child}, state) do
    case Map.get(state.children, child) do
      %Child{status: :pending} = entry ->
        state = %{
          state
          | children: Map.put(state.children, child, %{entry | status: :queued}),
            pending_count: max(0, state.pending_count - 1)
        }

        {state, actions} = enqueue_accepted_child(state, child)
        {:keep_state, state, actions}

      _ ->
        :keep_state_and_data
    end
  end

  def handle_event(:info, {:passive_failed, child}, state) do
    {:keep_state, remove_child(state, child)}
  end

  def handle_event(:info, {:passive_failed, child, reason}, state) do
    Logger.debug(
      "Passive TCP handshake failed after SYN-ACK retry exhaustion: #{inspect(reason)}"
    )

    {:keep_state, remove_child(state, child)}
  end

  def handle_event(
        :info,
        {:DOWN, monitor, :process, _connection_supervisor, reason},
        %__MODULE__{connection_supervisor_monitor: monitor} = state
      ) do
    Logger.warning("TCP listener connection supervisor exited unexpectedly: #{inspect(reason)}")
    Application.deregister_listener(state.local_addr, state.local_port)
    Application.deregister_bound_socket(state.local_addr, state.local_port)

    {:next_state, :closed, closed_data(state), close_accept_actions(state)}
  end

  def handle_event(:info, {:DOWN, monitor, :process, _caller, _reason}, state) do
    case take_waiter_by_monitor(state, monitor) do
      {:ok, waiter, state} ->
        release_waiter_monitor(waiter)
        {:keep_state, state, cancel_waiter_timer_actions(waiter)}

      :error ->
        :keep_state_and_data
    end
  end

  def handle_event({:call, from}, :close, state) do
    {closed_data, actions} = close(state)
    {:next_state, :closed, closed_data, actions ++ [{:reply, from, :ok}]}
  end

  def handle_event({:call, from}, :sockname, state) do
    sockaddr = Address.sockaddr_in6(state.local_addr, state.local_port)
    {:keep_state_and_data, {:reply, from, {:ok, sockaddr}}}
  end

  def handle_event({:call, from}, {:bind, _address}, _state) do
    {:keep_state_and_data, {:reply, from, {:error, :einval}}}
  end

  def handle_event({:call, from}, {:listen, _backlog}, _state) do
    {:keep_state_and_data, {:reply, from, {:error, :einval}}}
  end

  def handle_event({:call, from}, {:connect, _address, _timeout}, _state) do
    {:keep_state_and_data, {:reply, from, {:error, :einval}}}
  end

  def handle_event({:call, from}, {:send, _data, _timeout}, _state) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  def handle_event({:call, from}, {:recv, _length, _timeout}, _state) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  def handle_event({:call, from}, {:shutdown, _how}, _state) do
    {:keep_state_and_data, {:reply, from, {:error, :enotconn}}}
  end

  def handle_event({:call, from}, _event, _state) do
    {:keep_state_and_data, {:reply, from, {:error, :einval}}}
  end

  def handle_event(:info, _message, _state), do: :keep_state_and_data
  def handle_event(_event_type, _event, _state), do: :keep_state_and_data

  @spec close(t()) :: {map(), [term()]}
  def close(state) do
    close_result = ConnectionSupervisor.close(state.connection_supervisor)
    Process.demonitor(state.connection_supervisor_monitor, [:flush])
    Application.deregister_listener(state.local_addr, state.local_port)
    Application.deregister_bound_socket(state.local_addr, state.local_port)

    {closed_data_after_close(state, close_result), close_accept_actions(state)}
  end

  @spec terminate(t()) :: :ok
  def terminate(state) do
    close_result = ConnectionSupervisor.close(state.connection_supervisor)
    Process.demonitor(state.connection_supervisor_monitor, [:flush])
    Application.deregister_listener(state.local_addr, state.local_port)
    Application.deregister_bound_socket(state.local_addr, state.local_port)

    notify_accept_closure(state)
    log_close_failure(close_result)

    :ok
  end

  defp listen_addr_matches?(<<0::128>>, _dst_addr), do: true
  defp listen_addr_matches?(local_addr, dst_addr), do: local_addr == dst_addr

  defp backlog_full?(state) do
    state.pending_count + length(state.accept_queue) >= state.backlog
  end

  defp passive_link(peer_addr, local_addr) do
    case Application.lookup_link(peer_addr) do
      {link, {^local_addr, mtu}} -> {:ok, link, mtu}
      _ -> :error
    end
  end

  defp passive_connection_opts(state, src_addr, dst_addr, src_port, dst_port, segment) do
    with true <- listen_addr_matches?(state.local_addr, dst_addr),
         false <- backlog_full?(state),
         {:ok, link, mtu} <- passive_link(src_addr, dst_addr) do
      {:ok,
       %{
         src_addr: src_addr,
         dst_addr: dst_addr,
         src_port: src_port,
         dst_port: dst_port,
         segment: segment,
         link: link,
         mtu: mtu,
         socket_opts: state.socket_opts
       }}
    else
      _ -> :ignore
    end
  end

  defp start_passive_child(state, opts) do
    case ConnectionSupervisor.start_child(state.connection_supervisor, opts) do
      {:ok, child} ->
        {:keep_state,
         %{
           state
           | pending_count: state.pending_count + 1,
             children: Map.put(state.children, child, %Child{status: :pending})
         }}

      {:error, :closed} ->
        :keep_state_and_data

      {:error, reason} ->
        state = record_passive_start_failure(state, opts, reason)
        {:keep_state, state}
    end
  end

  defp record_passive_start_failure(state, opts, reason) do
    failures = state.passive_start_failures + 1

    if sampled_passive_start_failure?(failures) do
      peer = Address.sockaddr_in6(opts.src_addr, opts.src_port)

      Logger.warning(
        "TCP listener could not start passive child (sampled failure ##{failures}) " <>
          "for peer #{inspect(peer)}: #{inspect(reason)}"
      )
    end

    %{state | passive_start_failures: failures}
  end

  defp sampled_passive_start_failure?(failures) do
    failures > 0 and Bitwise.band(failures, failures - 1) == 0
  end

  defp remove_child(state, child) do
    case Map.pop(state.children, child) do
      {%Child{status: :pending}, children} ->
        %{state | children: children, pending_count: max(0, state.pending_count - 1)}

      {%Child{status: :queued}, children} ->
        accept_queue = Enum.reject(state.accept_queue, &(&1.child == child))
        %{state | children: children, accept_queue: accept_queue}

      {nil, _children} ->
        state
    end
  end

  defp enqueue_accepted_child(state, child) do
    state = %{state | accept_queue: state.accept_queue ++ [%Accepted{child: child}]}
    fulfill_accept_waiter(state)
  end

  defp fulfill_accept_waiter(state), do: fulfill_accept_waiter(state, [])

  defp fulfill_accept_waiter(state, actions) do
    case take_live_waiter(state, actions) do
      {:ok, waiter, state, actions} ->
        caller = waiter_caller(waiter)

        case take_accepted_child(state, caller) do
          {:ok, child, state} ->
            reply_or_reap_claimed_child(waiter, caller, child, state, actions)

          {:empty, state} ->
            {%{state | accept_waiters: [waiter | state.accept_waiters]}, actions}

          {:closed, state} ->
            {%{state | accept_waiters: [waiter | state.accept_waiters]}, actions}

          {:caller_down, state} ->
            release_waiter_monitor(waiter)
            fulfill_accept_waiter(state, actions ++ cancel_waiter_timer_actions(waiter))
        end

      {:none, state, actions} ->
        fulfill_accept_selects(state, actions)
    end
  end

  defp fulfill_accept_selects(%{accept_selects: selects} = state, actions) when selects != [] do
    notify_selects(selects)

    {%{state | accept_selects: []}, actions}
  end

  defp fulfill_accept_selects(state, actions), do: {state, actions}

  defp reply_or_reap_claimed_child(waiter, caller, child, state, actions) do
    if Process.alive?(caller) do
      release_waiter_monitor(waiter)

      {state,
       actions ++ cancel_waiter_timer_actions(waiter) ++ [{:reply, waiter.from, {:ok, child}}]}
    else
      # A caller can die after the supervisor has released the child. It must
      # not become an unowned pre-accept connection. Reaping it leaves the
      # listener's backlog and registry reusable; #131 will define any future
      # post-accept ownership transfer protocol.
      Process.exit(child, :shutdown)
      release_waiter_monitor(waiter)
      fulfill_accept_waiter(state, actions ++ cancel_waiter_timer_actions(waiter))
    end
  end

  defp take_accepted_child(state, caller) do
    case state.accept_queue do
      [%Accepted{child: child} = accepted | rest] ->
        state = %{state | accept_queue: rest}

        case claim_child(state, child, caller) do
          {:ok, state} -> {:ok, child, state}
          {:stale, state} -> take_accepted_child(state, caller)
          {:closed, state} -> {:closed, %{state | accept_queue: [accepted | rest]}}
          {:caller_down, state} -> {:caller_down, %{state | accept_queue: [accepted | rest]}}
        end

      [] ->
        {:empty, state}
    end
  end

  defp claim_child(state, child, caller) do
    case ConnectionSupervisor.claim(state.connection_supervisor, child, caller) do
      :ok -> {:ok, %{state | children: Map.delete(state.children, child)}}
      {:error, :not_queued} -> {:stale, remove_child(state, child)}
      {:error, :closed} -> {:closed, state}
      {:error, :caller_down} -> {:caller_down, state}
    end
  end

  defp wait_for_accept(state, from, timeout) do
    {:keep_state, state, [{:next_event, :internal, {:wait_accept, from, timeout}}]}
  end

  defp closed_data_after_close(state, result) do
    log_close_failure(result)
    closed_data(state)
  end

  defp closed_data(state), do: %{socket_opts: state.socket_opts}

  defp log_close_failure({:error, :closed}) do
    Logger.warning("TCP listener connection supervisor was unavailable during close")
  end

  defp log_close_failure(:ok), do: :ok

  defp close_accept_actions(state) do
    settle_accepts(state, fn waiter ->
      release_waiter_monitor(waiter)
      cancel_waiter_timer_actions(waiter) ++ [{:reply, waiter.from, {:error, :closed}}]
    end)
  end

  defp notify_accept_closure(state) do
    settle_accepts(state, fn waiter ->
      release_waiter_monitor(waiter)
      :gen_statem.reply(waiter.from, {:error, :closed})
      []
    end)

    :ok
  end

  defp settle_accepts(state, settle_waiter) do
    notify_selects(state.accept_selects)
    Enum.flat_map(state.accept_waiters, settle_waiter)
  end

  defp notify_selects(selects) do
    Enum.each(selects, fn {caller, ref} ->
      send(caller, {:"$socket", self(), :select, ref})
    end)
  end

  defp new_waiter({caller, _tag} = from, id, timer) do
    %Waiter{from: from, id: id, timer: timer, monitor: Process.monitor(caller)}
  end

  defp waiter_caller(%Waiter{from: {caller, _tag}}), do: caller

  defp release_waiter_monitor(%Waiter{monitor: monitor}) do
    Process.demonitor(monitor, [:flush])
    :ok
  end

  defp cancel_waiter_timer_actions(%Waiter{timer: nil}), do: []

  defp cancel_waiter_timer_actions(%Waiter{timer: timer}) do
    [{{:timeout, timer}, :cancel}]
  end

  defp take_live_waiter(state, actions) do
    case state.accept_waiters do
      [waiter | rest] ->
        state = %{state | accept_waiters: rest}

        if Process.alive?(waiter_caller(waiter)) do
          {:ok, waiter, state, actions}
        else
          release_waiter_monitor(waiter)
          take_live_waiter(state, actions ++ cancel_waiter_timer_actions(waiter))
        end

      [] ->
        {:none, state, actions}
    end
  end

  defp take_waiter_by_id(state, id), do: take_waiter(state, &(&1.id == id))
  defp take_waiter_by_monitor(state, monitor), do: take_waiter(state, &(&1.monitor == monitor))

  defp take_waiter(state, predicate) do
    case Enum.split_while(state.accept_waiters, &(not predicate.(&1))) do
      {before, [waiter | remaining]} ->
        {:ok, waiter, %{state | accept_waiters: before ++ remaining}}

      {_before, []} ->
        :error
    end
  end
end
