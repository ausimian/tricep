defmodule Tricep.IntegrationCase do
  @moduledoc """
  Test case template for integration tests that require TUN device access.

  These tests require root privileges or CAP_NET_ADMIN capability.
  They are excluded by default and can be run with:

      mix test --include integration

  Or run only integration tests:

      mix test --only integration
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      use ExUnit.Case, async: false

      @moduletag :integration

      import Tricep.IntegrationCase
    end
  end

  @doc """
  Creates a TUN link for testing and returns it.
  The link is automatically cleaned up when the test process exits.
  """
  def create_test_link(opts \\ []) do
    ifaddr = Keyword.get(opts, :ifaddr, "fd00::1")
    dstaddr = Keyword.get(opts, :dstaddr, "fd00::2")
    netmask = Keyword.get(opts, :netmask, "ffff:ffff:ffff:ffff::")
    mtu = Keyword.get(opts, :mtu, 1500)

    {:ok, link} =
      Tricep.Link.new(
        ifaddr: ifaddr,
        dstaddr: dstaddr,
        netmask: netmask,
        mtu: mtu
      )

    link
  end

  @doc """
  Creates a listening TCP socket on the kernel network stack.
  Returns `{:ok, listen_socket}` or `{:error, reason}`.
  """
  def create_kernel_listener(addr, port) do
    with {:ok, sock} <- :socket.open(:inet6, :stream, :tcp),
         :ok <- :socket.setopt(sock, {:socket, :reuseaddr}, true),
         :ok <- :socket.bind(sock, %{family: :inet6, addr: addr, port: port}),
         :ok <- :socket.listen(sock) do
      {:ok, sock}
    end
  end

  @doc """
  Accepts a connection on the listener socket with a timeout.
  """
  def accept_connection(listen_sock, timeout \\ 5_000) do
    :socket.accept(listen_sock, timeout)
  end
end
