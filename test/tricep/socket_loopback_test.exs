defmodule Tricep.SocketLoopbackTest do
  use ExUnit.Case, async: false

  defmodule LoopbackLink do
    use GenServer

    def start_link(opts) do
      GenServer.start_link(__MODULE__, opts)
    end

    @impl true
    def init(opts) do
      client_addr = Keyword.fetch!(opts, :client_addr)
      server_addr = Keyword.fetch!(opts, :server_addr)
      mtu = Keyword.get(opts, :mtu, 1500)

      :ok = Tricep.Application.register_link(client_addr, {server_addr, mtu})
      :ok = Tricep.Application.register_link(server_addr, {client_addr, mtu})

      {:ok, %{client_addr: client_addr, server_addr: server_addr}}
    end

    @impl true
    def handle_info({:send, packet}, state) do
      with {:ok, %{next_header: 6, src: src, dst: dst, payload: segment}} <-
             Tricep.Ip.parse(packet) do
        Tricep.Socket.handle_packet(src, dst, segment)
      end

      {:noreply, state}
    end

    @impl true
    def terminate(_reason, state) do
      Tricep.Application.deregister_link(state.client_addr)
      Tricep.Application.deregister_link(state.server_addr)
      :ok
    end
  end

  @port 10_180

  setup do
    id = System.unique_integer([:positive]) |> rem(0xFF00)
    client_id = id
    server_id = id + 1
    client_addr = addr_bin(client_id)
    server_addr = addr_bin(server_id)

    {:ok, link} = LoopbackLink.start_link(client_addr: client_addr, server_addr: server_addr)

    on_exit(fn -> stop_loopback_link(link) end)

    %{
      client_addr: client_addr,
      server_addr: server_addr,
      server_tuple: addr_tuple(server_id),
      server_sockaddr: %{family: :inet6, addr: addr_tuple(server_id), port: @port}
    }
  end

  test "client and listener complete a full handshake and exchange data both ways", ctx do
    {client, server, listener} = establish_loopback_connection(ctx)

    assert Tricep.send(client, "client to server") == :ok
    assert Tricep.recv(server, 0, 2_000) == {:ok, "client to server"}

    assert Tricep.send(server, "server to client") == :ok
    assert Tricep.recv(client, 0, 2_000) == {:ok, "server to client"}

    close_sockets([client, server, listener])
  end

  test "segments and reassembles large payloads in both directions", ctx do
    {client, server, listener} = establish_loopback_connection(ctx)

    client_payload = patterned_payload(12_345, 17)
    server_payload = patterned_payload(9_876, 53)

    assert Tricep.send(client, client_payload) == :ok
    assert Tricep.recv(server, byte_size(client_payload), 2_000) == {:ok, client_payload}

    assert Tricep.send(server, server_payload) == :ok
    assert Tricep.recv(client, byte_size(server_payload), 2_000) == {:ok, server_payload}

    close_sockets([client, server, listener])
  end

  test "handles many queued messages in both directions before either side drains", ctx do
    {client, server, listener} = establish_loopback_connection(ctx)

    client_chunks = for n <- 1..30, do: "client:#{n}:" <> patterned_payload(n * 7, n)
    server_chunks = for n <- 1..30, do: "server:#{n}:" <> patterned_payload(n * 5, n + 100)
    client_stream = IO.iodata_to_binary(client_chunks)
    server_stream = IO.iodata_to_binary(server_chunks)

    Enum.each(client_chunks, fn chunk ->
      assert Tricep.send(client, chunk) == :ok
    end)

    Enum.each(server_chunks, fn chunk ->
      assert Tricep.send(server, chunk) == :ok
    end)

    assert Tricep.recv(server, byte_size(client_stream), 2_000) == {:ok, client_stream}
    assert Tricep.recv(client, byte_size(server_stream), 2_000) == {:ok, server_stream}

    close_sockets([client, server, listener])
  end

  defp establish_loopback_connection(ctx) do
    {:ok, listener} = Tricep.open(:inet6, :stream, :tcp)

    assert Tricep.bind(listener, %{family: :inet6, addr: ctx.server_tuple, port: @port}) == :ok
    assert Tricep.listen(listener, 4) == :ok

    accept_task = Task.async(fn -> Tricep.accept(listener, 2_000) end)

    {:ok, client} = Tricep.open(:inet6, :stream, :tcp)

    connect_task =
      Task.async(fn ->
        Tricep.connect(client, ctx.server_sockaddr, 2_000)
      end)

    assert Task.await(connect_task, 2_000) == :ok
    assert {:ok, server} = Task.await(accept_task, 2_000)

    {client, server, listener}
  end

  defp close_sockets(sockets) do
    Enum.each(sockets, &stop_process/1)
  end

  defp stop_loopback_link(pid) when is_pid(pid) do
    if Process.alive?(pid) do
      GenServer.stop(pid, :normal, 1_000)
    end
  catch
    :exit, :noproc -> :ok
    :exit, {:noproc, _} -> :ok
  end

  defp stop_process(pid) when is_pid(pid) do
    if Process.alive?(pid) do
      Process.unlink(pid)
      Process.exit(pid, :kill)
    end
  catch
    :exit, :noproc -> :ok
    :exit, {:noproc, _} -> :ok
  end

  defp addr_bin(id), do: <<0xFD00::16, 0::96, id::16>>
  defp addr_tuple(id), do: {0xFD00, 0, 0, 0, 0, 0, 0, id}

  defp patterned_payload(size, salt) do
    for offset <- 0..(size - 1), into: <<>> do
      <<rem(offset + salt, 256)>>
    end
  end
end
