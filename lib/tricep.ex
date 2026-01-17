defmodule Tricep do
  @moduledoc """
  A userspace TCP/IP stack for Elixir.

  Tricep provides a socket-like API for TCP connections that bypasses the
  kernel's network stack. This is useful for scenarios where you need direct
  control over the network interface, such as VPN applications, network
  testing, or custom protocol implementations.

  ## Usage

  The API mirrors Erlang's `:socket` module:

      # Open a socket
      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)

      # Connect to a remote host
      :ok = Tricep.connect(socket, %{family: :inet6, addr: {0, 0, 0, 0, 0, 0, 0, 1}, port: 8080})

      # Send data
      :ok = Tricep.send(socket, "Hello, world!")

      # Receive data
      {:ok, data} = Tricep.recv(socket)

      # Close the socket
      :ok = Tricep.close(socket)

  ## Timeout Options

  The `connect/3`, `send/3`, and `recv/3` functions accept a timeout parameter:

    * Integer (milliseconds) - Block up to the specified time, returns `{:error, :timeout}` if exceeded
    * `:infinity` (default) - Block indefinitely until the operation completes
    * `:nowait` - Return immediately with `{:select, select_info}` if the operation would block

  ## Non-blocking Operations

  When using `:nowait`, operations that would block return a select tuple:

      {:select, {:select_info, operation, ref}}

  When the operation can proceed, the caller receives a message:

      {:"$socket", socket_pid, :select, ref}

  The caller can then retry the operation to complete it.
  """

  @doc """
  Opens a new TCP socket.

  Currently only IPv6 stream (TCP) sockets are supported.

  ## Arguments

    * `domain` - The address family, must be `:inet6`
    * `type` - The socket type, must be `:stream`
    * `protocol` - The protocol (`:tcp`, `:default`, or a map of options)

  ## Returns

    * `{:ok, socket}` - A socket pid on success
    * `{:error, :unsupported}` - If the domain/type/protocol combination is not supported

  ## Examples

      {:ok, socket} = Tricep.open(:inet6, :stream, :tcp)
      {:ok, socket} = Tricep.open(:inet6, :stream, :default)
      {:ok, socket} = Tricep.open(:inet6, :stream, %{})
  """
  @spec open(:inet6, :stream, :tcp | :default | map()) :: {:ok, pid()} | {:error, :unsupported}
  def open(domain, type, protocol)

  def open(:inet6, :stream, protocol) when protocol in [:tcp, :default] do
    open(:inet6, :stream, protocol, %{})
  end

  def open(:inet6, :stream, opts) when is_map(opts) do
    open(:inet6, :stream, :default, opts)
  end

  def open(_, _, _) do
    {:error, :unsupported}
  end

  @doc """
  Opens a new TCP socket with options.

  This is the 4-arity version that accepts explicit options.

  ## Arguments

    * `domain` - The address family, must be `:inet6`
    * `type` - The socket type, must be `:stream`
    * `protocol` - The protocol (`:tcp` or `:default`)
    * `opts` - A map of socket options (currently unused, reserved for future use)

  ## Returns

    * `{:ok, socket}` - A socket pid on success
    * `{:error, :unsupported}` - If the domain/type/protocol combination is not supported
  """
  @spec open(:inet6, :stream, :tcp | :default, map()) :: {:ok, pid()} | {:error, :unsupported}
  def open(domain, type, protocol, opts)

  def open(:inet6, :stream, :default, opts) do
    open(:inet6, :stream, :tcp, opts)
  end

  def open(:inet6, :stream, :tcp, opts) when is_map(opts) do
    Tricep.Socket.start_link(opts: opts)
  end

  def open(_, _, _, _) do
    {:error, :unsupported}
  end

  @typedoc """
  Timeout value for socket operations.

    * Non-negative integer - timeout in milliseconds
    * `:infinity` - wait indefinitely
    * `:nowait` - return immediately with select info if operation would block
  """
  @type socket_timeout :: non_neg_integer() | :infinity | :nowait

  @typedoc """
  Select info returned when an operation would block with `:nowait` timeout.

  The tuple contains the operation type (`:connect`, `:recv`, or `:send`) and
  a unique reference. When the operation can proceed, the caller receives
  `{:"$socket", socket_pid, :select, ref}`.
  """
  @type select_info :: {:select_info, :connect | :recv | :send, reference()}

  @doc """
  Connects a socket to a remote address.

  Initiates the TCP three-way handshake to establish a connection.

  ## Arguments

    * `socket` - The socket pid returned by `open/3`
    * `address` - The remote address as a sockaddr_in6 map with keys:
      * `:family` - Must be `:inet6`
      * `:addr` - IPv6 address as an 8-tuple of integers
      * `:port` - Port number
    * `timeout` - How long to wait (default: `:infinity`)

  ## Returns

    * `:ok` - Connection established successfully
    * `{:error, :timeout}` - Connection timed out (with integer timeout)
    * `{:error, :econnrefused}` - Connection refused (RST received)
    * `{:error, :etimedout}` - TCP-level timeout (max retransmissions exceeded)
    * `{:select, select_info}` - Operation would block (with `:nowait` timeout)

  ## Examples

      # Blocking connect
      :ok = Tricep.connect(socket, %{family: :inet6, addr: {0, 0, 0, 0, 0, 0, 0, 1}, port: 8080})

      # Connect with timeout
      case Tricep.connect(socket, address, 5000) do
        :ok -> :connected
        {:error, :timeout} -> :timed_out
      end

      # Non-blocking connect
      {:select, {:select_info, :connect, ref}} = Tricep.connect(socket, address, :nowait)
      receive do
        {:"$socket", ^socket, :select, ^ref} ->
          :ok = Tricep.connect(socket, address, :nowait)
      end
  """
  @spec connect(pid(), :socket.sockaddr_in6(), socket_timeout()) ::
          :ok | {:error, atom()} | {:select, select_info()}
  def connect(socket, address, timeout \\ :infinity)

  def connect(socket, address, timeout) when is_pid(socket) do
    Tricep.Socket.connect(socket, address, timeout)
  end

  @doc """
  Sends data on a connected socket.

  Queues data for transmission over the established TCP connection.

  ## Arguments

    * `socket` - The socket pid returned by `open/3`
    * `data` - Binary data to send
    * `timeout` - How long to wait if send buffer is full (default: `:infinity`)

  ## Returns

    * `:ok` - Data queued for transmission
    * `{:error, :enotconn}` - Socket is not connected
    * `{:error, :epipe}` - Socket is closing or closed
    * `{:error, :timeout}` - Timed out waiting for send window (with integer timeout)
    * `{:select, select_info}` - Send window exhausted (with `:nowait` timeout)

  ## Flow Control

  If the remote peer's receive window is full, the send operation will block
  (or return a select tuple with `:nowait`) until the window opens. ACKs from
  the peer advance the window and allow more data to be sent.

  ## Examples

      # Simple send
      :ok = Tricep.send(socket, "Hello, world!")

      # Send with timeout
      case Tricep.send(socket, large_data, 5000) do
        :ok -> :sent
        {:error, :timeout} -> :buffer_full
      end

      # Non-blocking send
      case Tricep.send(socket, data, :nowait) do
        :ok -> :sent
        {:select, {:select_info, :send, ref}} ->
          receive do
            {:"$socket", ^socket, :select, ^ref} ->
              Tricep.send(socket, data, :nowait)
          end
      end
  """
  @spec send(pid(), binary(), socket_timeout()) ::
          :ok | {:error, atom()} | {:select, select_info()}
  def send(socket, data, timeout \\ :infinity)

  def send(socket, data, timeout) when is_pid(socket) and is_binary(data) do
    Tricep.Socket.send_data(socket, data, timeout)
  end

  @doc """
  Receives data from a connected socket.

  Retrieves data that has been received from the remote peer.

  ## Arguments

    * `socket` - The socket pid returned by `open/3`
    * `length` - Number of bytes to receive (default: `0`)
      * `0` - Return all available data
      * `n` - Return exactly `n` bytes (blocks until available)
    * `timeout` - How long to wait for data (default: `:infinity`)

  ## Returns

    * `{:ok, data}` - Received data as a binary
    * `{:error, :enotconn}` - Socket is not connected
    * `{:error, :closed}` - Connection closed by peer (FIN received)
    * `{:error, :timeout}` - Timed out waiting for data (with integer timeout)
    * `{:select, select_info}` - No data available (with `:nowait` timeout)

  ## Examples

      # Receive all available data
      {:ok, data} = Tricep.recv(socket)

      # Receive exactly 1024 bytes
      {:ok, data} = Tricep.recv(socket, 1024)

      # Receive with timeout
      case Tricep.recv(socket, 0, 5000) do
        {:ok, data} -> handle_data(data)
        {:error, :timeout} -> :no_data
      end

      # Non-blocking receive
      case Tricep.recv(socket, 0, :nowait) do
        {:ok, data} -> handle_data(data)
        {:select, {:select_info, :recv, ref}} ->
          receive do
            {:"$socket", ^socket, :select, ^ref} ->
              {:ok, data} = Tricep.recv(socket, 0, :nowait)
              handle_data(data)
          end
      end
  """
  @spec recv(pid(), non_neg_integer(), socket_timeout()) ::
          {:ok, binary()} | {:error, atom()} | {:select, select_info()}
  def recv(socket, length \\ 0, timeout \\ :infinity)

  def recv(socket, length, timeout) when is_pid(socket) do
    Tricep.Socket.recv(socket, length, timeout)
  end

  @doc """
  Closes a socket.

  Initiates a graceful TCP connection shutdown by sending a FIN to the peer.
  The socket transitions through the FIN_WAIT states before fully closing.

  ## Arguments

    * `socket` - The socket pid returned by `open/3`

  ## Returns

    * `:ok` - Close initiated successfully
    * `{:error, :enotconn}` - Socket is not connected

  ## Examples

      :ok = Tricep.close(socket)
  """
  @spec close(pid()) :: :ok | {:error, atom()}
  def close(socket) when is_pid(socket) do
    Tricep.Socket.close(socket)
  end

  @doc """
  Shuts down part of a full-duplex connection.

  Unlike `close/1` which initiates a full graceful close, `shutdown/2` allows
  closing only one direction of the connection (half-close).

  ## Arguments

    * `socket` - The socket pid returned by `open/3`
    * `how` - Which side(s) to shut down:
      * `:read` - Disable receives (local only, no network action). Subsequent
        `recv/3` calls return `{:error, :closed}` after any buffered data is consumed.
      * `:write` - Disable sends and send FIN to peer. Subsequent `send/3` calls
        return `{:error, :epipe}`.
      * `:read_write` - Disable both directions (equivalent to `close/1`).

  ## Returns

    * `:ok` - Shutdown successful
    * `{:error, :enotconn}` - Socket is not connected

  ## Examples

      # Half-close: signal no more data to send, but can still receive
      :ok = Tricep.shutdown(socket, :write)

      # Stop receiving data, but can still send
      :ok = Tricep.shutdown(socket, :read)

      # Full shutdown (same as close)
      :ok = Tricep.shutdown(socket, :read_write)
  """
  @spec shutdown(pid(), :read | :write | :read_write) :: :ok | {:error, atom()}
  def shutdown(socket, how) when is_pid(socket) and how in [:read, :write, :read_write] do
    Tricep.Socket.shutdown(socket, how)
  end
end
