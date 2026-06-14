defmodule Tricep.TunLinkTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Tricep.DummyLink
  alias Tricep.Ip
  alias Tricep.Tcp
  alias Tricep.TunLink

  @local_addr_str "fd00::1"
  @remote_addr_str "fd00::2"
  @port 8080
  @read_tun_again {:keep_state_and_data, {:next_event, :internal, :read_tun}}

  setup do
    {:ok, local_addr} = Tricep.Address.from(@local_addr_str)
    {:ok, remote_addr} = Tricep.Address.from(@remote_addr_str)

    {:ok, link} =
      DummyLink.start_link(local_addr: local_addr, remote_addr: remote_addr, owner: self())

    on_exit(fn -> stop_link(link) end)

    %{link: link, local_addr: local_addr, remote_addr: remote_addr}
  end

  describe "handle_ip_packet/2" do
    test "drops malformed IPv6 packets without crashing", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      invalid_length =
        <<6::4, 0::8, 0::20, 4::16, 6::8, 64::8, local_addr::binary-size(16),
          remote_addr::binary-size(16), 1, 2>>

      malformed_extension = Ip.wrap(local_addr, remote_addr, 0, <<6, 1, 0, 0, 0, 0, 0, 0>>)

      for packet <- [
            <<>>,
            <<6::4, 0::28>>,
            <<4::4, 0::316>>,
            invalid_length,
            malformed_extension
          ] do
        assert TunLink.handle_ip_packet(packet, tun_state()) == @read_tun_again
      end
    end

    test "drops bad TCP checksum through IPv6 packet flow", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn_parsed = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn_parsed.seq + 1,
          [:syn, :ack],
          32768
        )

      corrupt_packet = Ip.wrap(local_addr, remote_addr, :tcp, corrupt_checksum(syn_ack_segment))

      assert TunLink.handle_ip_packet(corrupt_packet, tun_state()) == @read_tun_again

      refute Task.yield(task, 100)
      refute_receive {:dummy_link_packet, _link, _packet}, 100

      valid_packet = Ip.wrap(local_addr, remote_addr, :tcp, syn_ack_segment)

      assert TunLink.handle_ip_packet(valid_packet, tun_state()) == @read_tun_again
      assert Task.await(task, 1000) == :ok
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000
    end

    test "Packet Too Big below IPv6 minimum is logged and clamps TCP send MSS", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(local_addr, remote_addr)
      {quoted_packet, _state} = quoted_tcp_packet(socket)

      icmp = <<2, 0, 0::16, 1200::32, quoted_packet::binary>>
      packet = Ip.wrap(local_addr, remote_addr, :icmpv6, icmp)

      log =
        capture_log(fn ->
          assert TunLink.handle_ip_packet(packet, tun_state()) == @read_tun_again
        end)

      assert log =~ "ICMPv6 Packet Too Big mtu=1200"

      wait_for_socket(socket, fn
        {:established, %{snd_mss: 1220}} -> true
        _state -> false
      end)
    end

    test "Destination Unreachable closes affected TCP socket and notifies waiters", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(local_addr, remote_addr)

      recv_task = Task.async(fn -> Tricep.recv(socket, 0, :infinity) end)

      wait_for_socket(socket, fn
        {:established, %{recv_waiters: waiters}} -> length(waiters) == 1
        _state -> false
      end)

      {quoted_packet, _state} = quoted_tcp_packet(socket)
      icmp = <<1, 0, 0::16, 0::32, quoted_packet::binary>>
      packet = Ip.wrap(local_addr, remote_addr, :icmpv6, icmp)

      log =
        capture_log(fn ->
          assert TunLink.handle_ip_packet(packet, tun_state()) == @read_tun_again
        end)

      assert log =~ "ICMPv6 enetunreach"
      assert Task.await(recv_task, 1000) == {:error, :enetunreach}
      assert {:closed, nil} = :sys.get_state(socket)
    end

    test "reassembles fragmented TCP packets before dispatch", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000
      <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
      syn_parsed = Tcp.parse_segment(syn_segment)
      <<src_port::16, _::binary>> = syn_segment

      syn_ack_segment =
        Tcp.build_segment(
          {{local_addr, @port}, {remote_addr, src_port}},
          5000,
          syn_parsed.seq + 1,
          [:syn, :ack],
          32768
        )

      <<fragment1::binary-size(16), fragment2::binary>> = syn_ack_segment
      identification = 1234
      state = tun_state()

      state =
        state
        |> handle_fragment_packet(local_addr, remote_addr, identification, 0, true, fragment1)

      refute Task.yield(task, 100)
      assert map_size(state.fragment_buffers) == 1

      state =
        state
        |> handle_fragment_packet(local_addr, remote_addr, identification, 16, false, fragment2)

      assert state.fragment_buffers == %{}
      assert Task.await(task, 1000) == :ok
      assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000
    end

    test "rejects malformed non-final fragment payload length", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      packet = fragment_packet(local_addr, remote_addr, 6, 1234, 0, true, "not-8")

      log =
        capture_log(fn ->
          assert {:keep_state, state, {:next_event, :internal, :read_tun}} =
                   TunLink.handle_ip_packet(packet, tun_state())

          assert state.fragment_buffers == %{}
        end)

      assert log =~ "Dropping malformed IPv6 fragment"
    end
  end

  defp establish_connection(local_addr, remote_addr) do
    {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

    task =
      Task.async(fn ->
        Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
      end)

    assert_receive {:dummy_link_packet, _link, syn_packet}, 1000
    <<_ip_header::binary-size(40), syn_segment::binary>> = syn_packet
    syn_parsed = Tcp.parse_segment(syn_segment)
    <<src_port::16, _::binary>> = syn_segment

    syn_ack_segment =
      Tcp.build_segment(
        {{local_addr, @port}, {remote_addr, src_port}},
        5000,
        syn_parsed.seq + 1,
        [:syn, :ack],
        32768
      )

    packet = Ip.wrap(local_addr, remote_addr, :tcp, syn_ack_segment)

    assert TunLink.handle_ip_packet(packet, tun_state()) == @read_tun_again
    assert Task.await(task, 1000) == :ok
    assert_receive {:dummy_link_packet, _link, _ack_packet}, 1000

    socket
  end

  defp quoted_tcp_packet(socket) do
    {:established, state} = :sys.get_state(socket)
    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    tcp_segment =
      Tcp.build_segment(
        state.pair,
        state.snd_nxt,
        state.rcv_nxt,
        [:ack],
        32768
      )

    {Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment), state}
  end

  defp handle_fragment_packet(state, src, dst, identification, offset, more_fragments?, payload) do
    packet = fragment_packet(src, dst, 6, identification, offset, more_fragments?, payload)

    assert {:keep_state, new_state, {:next_event, :internal, :read_tun}} =
             TunLink.handle_ip_packet(packet, state)

    new_state
  end

  defp fragment_packet(src, dst, next_header, identification, offset, more_fragments?, payload) do
    offset_units = div(offset, 8)
    more_flag = if more_fragments?, do: 1, else: 0
    offset_flags = offset_units |> Bitwise.bsl(3) |> Bitwise.bor(more_flag)

    fragment_header =
      <<next_header::8, 0::8, offset_flags::16, identification::32, payload::binary>>

    Ip.wrap(src, dst, 44, fragment_header)
  end

  defp tun_state do
    %TunLink{tun: self(), name: "testtun0", mtu: 1500}
  end

  defp wait_for_socket(socket, predicate, timeout \\ 1_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    wait_for_socket(socket, predicate, deadline, nil)
  end

  defp wait_for_socket(socket, predicate, deadline, last_state) do
    state = :sys.get_state(socket)

    cond do
      predicate.(state) ->
        state

      System.monotonic_time(:millisecond) >= deadline ->
        flunk("socket did not reach expected state; last state: #{inspect(last_state || state)}")

      true ->
        Process.sleep(1)
        wait_for_socket(socket, predicate, deadline, state)
    end
  end

  defp corrupt_checksum(segment) do
    <<prefix::binary-size(16), checksum::16, suffix::binary>> = segment
    prefix <> <<Bitwise.bxor(checksum, 0x0001)::16>> <> suffix
  end

  defp stop_link(link) do
    if Process.alive?(link) do
      GenServer.stop(link)
    end
  catch
    :exit, :noproc -> :ok
    :exit, {:noproc, _} -> :ok
  end
end
