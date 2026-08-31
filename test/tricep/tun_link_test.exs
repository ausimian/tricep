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
  @read_tun_again :keep_state_and_data

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

    test "a truncated RFC 4443 Packet Too Big quote clamps TCP send MSS", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(local_addr, remote_addr)

      :sys.replace_state(socket, fn
        {:established, state} ->
          {:established, %{state | tcb: %{state.tcb | snd_mss: 1460}}}
      end)

      original_packet = send_data_and_capture(socket, :binary.copy("x", 1400))
      quoted_packet = truncate_quoted_packet(original_packet)

      assert byte_size(quoted_packet) == 1232
      assert Ip.parse(quoted_packet) == {:error, :invalid_payload_length}

      assert {:ok, %{payload_length: 1420, payload: quoted_payload}} =
               Ip.parse_quoted(quoted_packet)

      assert byte_size(quoted_payload) == 1192

      icmp = icmpv6_error(local_addr, remote_addr, 2, 0, 1300, quoted_packet)
      packet = Ip.wrap(local_addr, remote_addr, :icmpv6, icmp)

      log =
        capture_log(fn ->
          assert TunLink.handle_ip_packet(packet, tun_state()) == @read_tun_again

          wait_for_socket(socket, fn
            {:established, %{tcb: %{snd_mss: 1240}}} -> true
            _state -> false
          end)
        end)

      assert log =~ "[info] ICMPv6 Packet Too Big mtu=1300 reduced TCP send MSS from 1460 to 1240"
    end

    test "drops ICMPv6 error with invalid checksum without applying it", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(local_addr, remote_addr)

      :sys.replace_state(socket, fn
        {:established, state} ->
          {:established, %{state | tcb: %{state.tcb | snd_mss: 1460}}}
      end)

      {quoted_packet, _state} = quoted_tcp_packet(socket)

      icmp =
        icmpv6_error(local_addr, remote_addr, 2, 0, 1300, quoted_packet)
        |> corrupt_icmpv6_checksum()

      packet = Ip.wrap(local_addr, remote_addr, :icmpv6, icmp)

      assert TunLink.handle_ip_packet(packet, tun_state()) == @read_tun_again
      assert {:established, %{tcb: %{snd_mss: 1460}}} = :sys.get_state(socket)
    end

    test "a forged out-of-flight Packet Too Big leaves send MSS unchanged", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(local_addr, remote_addr)

      :sys.replace_state(socket, fn
        {:established, state} ->
          {:established, %{state | tcb: %{state.tcb | snd_mss: 1460}}}
      end)

      quoted_packet = send_data_and_capture(socket, :binary.copy("x", 1400))
      {:established, state} = :sys.get_state(socket)

      forged_quote = replace_quoted_tcp_sequence(quoted_packet, state.tcb.snd_nxt)
      icmp = icmpv6_error(local_addr, remote_addr, 2, 0, 1300, forged_quote)
      packet = Ip.wrap(local_addr, remote_addr, :icmpv6, icmp)

      log =
        capture_log([level: :debug], fn ->
          assert TunLink.handle_ip_packet(packet, tun_state()) == @read_tun_again
          assert {:established, %{tcb: %{snd_mss: 1460}}} = :sys.get_state(socket)
        end)

      assert log =~ "[debug] Ignoring inapplicable ICMPv6 {:packet_too_big, 1300} quote"
      refute log =~ "[info] ICMPv6 Packet Too Big"
      assert {:established, %{tcb: %{snd_mss: 1460}}} = :sys.get_state(socket)
    end

    test "rejects a stale Packet Too Big quote after its data is acknowledged", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(local_addr, remote_addr)

      :sys.replace_state(socket, fn
        {:established, state} ->
          {:established, %{state | tcb: %{state.tcb | snd_mss: 1460}}}
      end)

      original_packet = send_data_and_capture(socket, :binary.copy("x", 1400))
      quoted_packet = truncate_quoted_packet(original_packet)
      {:established, sent_state} = :sys.get_state(socket)
      acknowledgement = acknowledge_quoted_packet(original_packet, sent_state)

      assert TunLink.handle_ip_packet(acknowledgement, tun_state()) == @read_tun_again

      wait_for_socket(socket, fn
        {:established, %{tcb: %{snd_una: send_unacknowledged, snd_nxt: send_next}}} ->
          send_unacknowledged == send_next

        _state ->
          false
      end)

      icmp = icmpv6_error(local_addr, remote_addr, 2, 0, 1300, quoted_packet)
      packet = Ip.wrap(local_addr, remote_addr, :icmpv6, icmp)

      assert TunLink.handle_ip_packet(packet, tun_state()) == @read_tun_again
      assert {:established, %{tcb: %{snd_mss: 1460}}} = :sys.get_state(socket)
    end

    test "a Packet Too Big for an unmatched four-tuple leaves sockets unchanged", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(local_addr, remote_addr)

      :sys.replace_state(socket, fn
        {:established, state} ->
          {:established, %{state | tcb: %{state.tcb | snd_mss: 1460}}}
      end)

      quoted_packet = send_data_and_capture(socket, :binary.copy("x", 1400))
      unmatched_quote = replace_quoted_tcp_source_port(quoted_packet, 0)
      icmp = icmpv6_error(local_addr, remote_addr, 2, 0, 1300, unmatched_quote)

      assert TunLink.handle_ip_packet(
               Ip.wrap(local_addr, remote_addr, :icmpv6, icmp),
               tun_state()
             ) == @read_tun_again

      assert {:established, %{tcb: %{snd_mss: 1460}}} = :sys.get_state(socket)
    end

    test "records applicable ICMPv6 errors as soft after synchronization", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(local_addr, remote_addr)
      quoted_packet = send_data_and_capture(socket)

      recv_task = Task.async(fn -> Tricep.recv(socket, 0, :infinity) end)

      wait_for_socket(socket, fn
        {:established, %{recv_waiters: waiters}} -> length(waiters) == 1
        _state -> false
      end)

      for {type, code, word, reason} <- [
            {1, 0, 0, :enetunreach},
            {3, 0, 0, :etimedout},
            {4, 0, 0, :eproto}
          ] do
        icmp = icmpv6_error(local_addr, remote_addr, type, code, word, quoted_packet)
        packet = Ip.wrap(local_addr, remote_addr, :icmpv6, icmp)
        assert TunLink.handle_ip_packet(packet, tun_state()) == @read_tun_again

        wait_for_socket(socket, fn
          {:established, %{soft_error: ^reason}} -> true
          _state -> false
        end)
      end

      assert {:established, %{soft_error: :eproto}} = :sys.get_state(socket)
      refute Task.yield(recv_task, 100)
      Task.shutdown(recv_task, :brutal_kill)
    end

    test "requires a matching quoted SYN while an active open is pending", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      task =
        Task.async(fn ->
          Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
        end)

      assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

      forged_quote = replace_quoted_tcp_flags(syn_packet, 0)
      forged_icmp = icmpv6_error(local_addr, remote_addr, 1, 1, 0, forged_quote)

      assert TunLink.handle_ip_packet(
               Ip.wrap(local_addr, remote_addr, :icmpv6, forged_icmp),
               tun_state()
             ) == @read_tun_again

      refute Task.yield(task, 100)

      valid_icmp = icmpv6_error(local_addr, remote_addr, 1, 1, 0, syn_packet)

      assert TunLink.handle_ip_packet(
               Ip.wrap(local_addr, remote_addr, :icmpv6, valid_icmp),
               tun_state()
             ) == @read_tun_again

      assert Task.await(task, 1000) == {:error, :eacces}
    end

    test "keeps active open alive for matching soft ICMPv6 errors", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      for {type, code, word, reason} <- [{3, 0, 0, :etimedout}, {4, 0, 0, :eproto}] do
        {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

        task =
          Task.async(fn ->
            Tricep.connect(socket, %{family: :inet6, addr: @local_addr_str, port: @port})
          end)

        assert_receive {:dummy_link_packet, _link, syn_packet}, 1000

        soft_icmp = icmpv6_error(local_addr, remote_addr, type, code, word, syn_packet)

        assert TunLink.handle_ip_packet(
                 Ip.wrap(local_addr, remote_addr, :icmpv6, soft_icmp),
                 tun_state()
               ) == @read_tun_again

        wait_for_socket(socket, fn
          {{:syn_sent, _}, %{soft_error: ^reason}} -> true
          _state -> false
        end)

        refute Task.yield(task, 100)
        assert_receive {:dummy_link_packet, _link, _syn_retransmission}, 1_500

        assert {{:syn_sent, _}, %{syn_retransmit_count: 1, soft_error: ^reason}} =
                 :sys.get_state(socket)

        hard_icmp = icmpv6_error(local_addr, remote_addr, 1, 1, 0, syn_packet)

        assert TunLink.handle_ip_packet(
                 Ip.wrap(local_addr, remote_addr, :icmpv6, hard_icmp),
                 tun_state()
               ) == @read_tun_again

        assert Task.await(task, 1_000) == {:error, :eacces}
      end
    end

    test "accepts an in-flight Packet Too Big quote across sequence wrap", %{
      local_addr: local_addr,
      remote_addr: remote_addr
    } do
      socket = establish_connection(local_addr, remote_addr)

      :sys.replace_state(socket, fn
        {:established, state} ->
          {:established,
           %{
             state
             | tcb: %{state.tcb | snd_una: 0xFFFFFFFE, snd_nxt: 2, snd_mss: 1460}
           }}
      end)

      {quoted_packet, _state} = quoted_tcp_packet(socket, 0)
      icmp = icmpv6_error(local_addr, remote_addr, 2, 0, 1300, quoted_packet)

      assert TunLink.handle_ip_packet(
               Ip.wrap(local_addr, remote_addr, :icmpv6, icmp),
               tun_state()
             ) == @read_tun_again

      wait_for_socket(socket, fn
        {:established, %{tcb: %{snd_mss: 1240}}} -> true
        _state -> false
      end)
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

    test "reassembles fragmented TCP packets after extension headers", %{
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
      identification = 5678
      state = tun_state()

      state =
        state
        |> handle_hop_by_hop_fragment_packet(
          local_addr,
          remote_addr,
          identification,
          0,
          true,
          fragment1
        )

      refute Task.yield(task, 100)
      assert map_size(state.fragment_buffers) == 1

      state =
        state
        |> handle_hop_by_hop_fragment_packet(
          local_addr,
          remote_addr,
          identification,
          16,
          false,
          fragment2
        )

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
          assert {:keep_state, state} =
                   TunLink.handle_ip_packet(packet, tun_state())

          assert state.fragment_buffers == %{}
        end)

      assert log =~ "Dropping malformed IPv6 fragment"
    end
  end

  describe "bounded transmit queue" do
    test "yields each ready read before admitting a socket send" do
      state = tun_state()

      # Model a continuously readable device. Every completed packet queues an
      # ordinary mailbox message instead of chaining another internal event, so a
      # socket admission already in the mailbox is serviced before the next
      # read. The bound is one additional read packet.
      packet = <<>>

      Enum.each(1..31, fn _ ->
        assert TunLink.handle_ip_packet(packet, state) == @read_tun_again
        assert_receive :read_tun
      end)

      from = {self(), make_ref()}
      send(self(), {:queued_socket_admission, from})

      assert TunLink.handle_ip_packet(packet, state) == @read_tun_again

      queued_message =
        receive do
          message -> message
        after
          100 -> :timeout
        end

      assert {:queued_socket_admission, ^from} = queued_message

      assert_receive :read_tun

      assert {:keep_state, admitted, [{:reply, ^from, :ok}, {:next_event, :internal, :drain_tx}]} =
               TunLink.handle_event({:call, from}, {:send, "payload"}, :ready, state)

      assert admitted.tx_queued_packets == 1
      assert admitted.tx_queued_bytes == byte_size("payload")
    end

    test "caps queued packet and byte ownership while the TUN writer is stalled" do
      handle = make_ref()

      state = %TunLink{
        tun: self(),
        name: "testtun0",
        mtu: 1500,
        tx_queue_packets_limit: 2,
        tx_queue_bytes_limit: 5
      }

      from = {self(), make_ref()}

      assert {:keep_state, queued, [{:reply, ^from, :ok}]} =
               TunLink.handle_event(
                 {:call, from},
                 {:send, <<1, 2>>},
                 {:waiting, handle},
                 state
               )

      assert queued.tx_queued_packets == 1
      assert queued.tx_queued_bytes == 2

      assert {:keep_state, queued, [{:reply, ^from, :ok}]} =
               TunLink.handle_event(
                 {:call, from},
                 {:send, <<3, 4, 5>>},
                 {:waiting, handle},
                 queued
               )

      assert queued.tx_queued_packets == 2
      assert queued.tx_queued_bytes == 5

      assert {:keep_state_and_data, {:reply, ^from, {:error, :eagain}}} =
               TunLink.handle_event(
                 {:call, from},
                 {:send, <<6>>},
                 {:waiting, handle},
                 queued
               )
    end

    test "drains queued sources round-robin after a stalled writer recovers" do
      handle = make_ref()
      source_a = self()
      source_b = spawn(fn -> Process.sleep(:infinity) end)

      on_exit(fn -> Process.exit(source_b, :kill) end)

      state = %TunLink{
        tun: self(),
        name: "testtun0",
        mtu: 1500,
        tx_queue_packets_limit: 4,
        tx_queue_bytes_limit: 16
      }

      {:keep_state, state, _} =
        TunLink.handle_event(
          {:call, {source_a, make_ref()}},
          {:send, "a1"},
          {:waiting, handle},
          state
        )

      {:keep_state, state, _} =
        TunLink.handle_event(
          {:call, {source_a, make_ref()}},
          {:send, "a2"},
          {:waiting, handle},
          state
        )

      {:keep_state, state, _} =
        TunLink.handle_event(
          {:call, {source_b, make_ref()}},
          {:send, "b1"},
          {:waiting, handle},
          state
        )

      assert {:keep_state, first, {:next_event, :internal, :send_pending_tx}} =
               TunLink.handle_event(:internal, :drain_tx, :ready, state)

      assert first.pending_tx == {source_a, "a1"}

      # Model completion without invoking the platform TUN NIF, then prove
      # the next owner is B rather than A's second packet.
      completed = %{
        first
        | pending_tx: nil,
          tx_queued_packets: first.tx_queued_packets - 1,
          tx_queued_bytes: first.tx_queued_bytes - 2
      }

      assert {:keep_state, second, {:next_event, :internal, :send_pending_tx}} =
               TunLink.handle_event(:internal, :drain_tx, :ready, completed)

      assert second.pending_tx == {source_b, "b1"}
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

  defp quoted_tcp_packet(socket, sequence \\ nil, flags \\ [:ack]) do
    {:established, state} = :sys.get_state(socket)
    {{src_addr, _src_port}, {dst_addr, _dst_port}} = state.pair

    sequence = sequence || state.tcb.snd_nxt

    tcp_segment =
      Tcp.build_segment(
        state.pair,
        sequence,
        state.tcb.rcv_nxt,
        flags,
        32768
      )

    {Ip.wrap(src_addr, dst_addr, :tcp, tcp_segment), state}
  end

  defp send_data_and_capture(socket, data \\ "in-flight") do
    assert Tricep.send(socket, data) == :ok
    assert_receive {:dummy_link_packet, _link, data_packet}, 1000
    data_packet
  end

  defp truncate_quoted_packet(packet), do: binary_part(packet, 0, 1232)

  defp acknowledge_quoted_packet(quoted_packet, state) do
    <<_ipv6_header::binary-size(40), tcp_segment::binary>> = quoted_packet
    %{seq: sequence, payload: payload} = Tcp.parse_segment(tcp_segment)
    {{src_addr, src_port}, {dst_addr, dst_port}} = state.pair

    acknowledgment =
      Tcp.build_segment(
        {{dst_addr, dst_port}, {src_addr, src_port}},
        state.tcb.rcv_nxt,
        sequence + byte_size(payload),
        [:ack],
        32768
      )

    Ip.wrap(dst_addr, src_addr, :tcp, acknowledgment)
  end

  defp replace_quoted_tcp_sequence(
         <<ipv6_and_ports::binary-size(44), _sequence::32, rest::binary>>,
         sequence
       ) do
    <<ipv6_and_ports::binary, sequence::32, rest::binary>>
  end

  defp replace_quoted_tcp_source_port(
         <<ipv6_header::binary-size(40), _source_port::16, rest::binary>>,
         source_port
       ) do
    <<ipv6_header::binary, source_port::16, rest::binary>>
  end

  defp replace_quoted_tcp_flags(<<prefix::binary-size(53), _flags::8, rest::binary>>, flags) do
    <<prefix::binary, flags::8, rest::binary>>
  end

  defp handle_fragment_packet(state, src, dst, identification, offset, more_fragments?, payload) do
    packet = fragment_packet(src, dst, 6, identification, offset, more_fragments?, payload)

    assert {:keep_state, new_state} =
             TunLink.handle_ip_packet(packet, state)

    new_state
  end

  defp handle_hop_by_hop_fragment_packet(
         state,
         src,
         dst,
         identification,
         offset,
         more_fragments?,
         payload
       ) do
    packet =
      hop_by_hop_fragment_packet(src, dst, 6, identification, offset, more_fragments?, payload)

    assert {:keep_state, new_state} =
             TunLink.handle_ip_packet(packet, state)

    new_state
  end

  defp fragment_packet(src, dst, next_header, identification, offset, more_fragments?, payload) do
    Ip.wrap(
      src,
      dst,
      44,
      fragment_header(next_header, identification, offset, more_fragments?, payload)
    )
  end

  defp hop_by_hop_fragment_packet(
         src,
         dst,
         next_header,
         identification,
         offset,
         more_fragments?,
         payload
       ) do
    hop_by_hop_header =
      <<44, 0, 0::48,
        fragment_header(next_header, identification, offset, more_fragments?, payload)::binary>>

    Ip.wrap(src, dst, 0, hop_by_hop_header)
  end

  defp fragment_header(next_header, identification, offset, more_fragments?, payload) do
    offset_units = div(offset, 8)
    more_flag = if more_fragments?, do: 1, else: 0
    offset_flags = offset_units |> Bitwise.bsl(3) |> Bitwise.bor(more_flag)

    <<next_header::8, 0::8, offset_flags::16, identification::32, payload::binary>>
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

  defp icmpv6_error(src, dst, type, code, word, quoted_packet) do
    without_checksum = <<type, code, 0::16, word::32, quoted_packet::binary>>
    checksum = icmpv6_checksum(src, dst, without_checksum)

    <<type, code, checksum::16, word::32, quoted_packet::binary>>
  end

  defp icmpv6_checksum(src, dst, payload) do
    Tricep.Nifs.checksum([
      src,
      dst,
      <<byte_size(payload)::32, 0::24, 58::8>>,
      payload
    ])
  end

  defp corrupt_icmpv6_checksum(<<type, code, checksum::16, rest::binary>>) do
    <<type, code, Bitwise.bxor(checksum, 0x0001)::16, rest::binary>>
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
