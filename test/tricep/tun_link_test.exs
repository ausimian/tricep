defmodule Tricep.TunLinkTest do
  use ExUnit.Case, async: false

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
  end

  defp tun_state do
    %TunLink{tun: self(), name: "testtun0", mtu: 1500}
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
