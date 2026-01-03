defmodule Tricep.DataBufferTest do
  use ExUnit.Case, async: true

  alias Tricep.DataBuffer

  describe "new/0" do
    test "creates empty buffer" do
      buffer = DataBuffer.new()
      assert DataBuffer.empty?(buffer)
      assert DataBuffer.size(buffer) == 0
    end
  end

  describe "append/2" do
    test "appends data to empty buffer" do
      buffer = DataBuffer.new()
      buffer = DataBuffer.append(buffer, "hello")

      assert DataBuffer.size(buffer) == 5
      refute DataBuffer.empty?(buffer)
    end

    test "appends multiple chunks" do
      buffer = DataBuffer.new()
      buffer = DataBuffer.append(buffer, "hello")
      buffer = DataBuffer.append(buffer, " ")
      buffer = DataBuffer.append(buffer, "world")

      assert DataBuffer.size(buffer) == 11
    end

    test "ignores empty binaries" do
      buffer = DataBuffer.new()
      buffer = DataBuffer.append(buffer, "hello")
      buffer = DataBuffer.append(buffer, <<>>)
      buffer = DataBuffer.append(buffer, "world")

      assert DataBuffer.size(buffer) == 10
    end
  end

  describe "take/2" do
    test "takes from empty buffer returns empty iodata" do
      buffer = DataBuffer.new()
      {taken, buffer} = DataBuffer.take(buffer, 10)

      assert IO.iodata_to_binary(taken) == <<>>
      assert DataBuffer.empty?(buffer)
    end

    test "takes zero bytes returns empty iodata" do
      buffer = DataBuffer.new() |> DataBuffer.append("hello")
      {taken, buffer} = DataBuffer.take(buffer, 0)

      assert IO.iodata_to_binary(taken) == <<>>
      assert DataBuffer.size(buffer) == 5
    end

    test "takes entire single chunk" do
      buffer = DataBuffer.new() |> DataBuffer.append("hello")
      {taken, buffer} = DataBuffer.take(buffer, 5)

      assert IO.iodata_to_binary(taken) == "hello"
      assert DataBuffer.empty?(buffer)
    end

    test "takes partial single chunk" do
      buffer = DataBuffer.new() |> DataBuffer.append("hello world")
      {taken, buffer} = DataBuffer.take(buffer, 5)

      assert IO.iodata_to_binary(taken) == "hello"
      assert DataBuffer.size(buffer) == 6

      {taken, buffer} = DataBuffer.take(buffer, 10)
      assert IO.iodata_to_binary(taken) == " world"
      assert DataBuffer.empty?(buffer)
    end

    test "takes across multiple chunks" do
      buffer =
        DataBuffer.new()
        |> DataBuffer.append("hello")
        |> DataBuffer.append(" ")
        |> DataBuffer.append("world")

      {taken, buffer} = DataBuffer.take(buffer, 7)

      assert IO.iodata_to_binary(taken) == "hello w"
      assert DataBuffer.size(buffer) == 4
    end

    test "takes more than available returns all" do
      buffer = DataBuffer.new() |> DataBuffer.append("hello")
      {taken, buffer} = DataBuffer.take(buffer, 100)

      assert IO.iodata_to_binary(taken) == "hello"
      assert DataBuffer.empty?(buffer)
    end

    test "sequential takes maintain FIFO order" do
      buffer =
        DataBuffer.new()
        |> DataBuffer.append("abc")
        |> DataBuffer.append("def")
        |> DataBuffer.append("ghi")

      {t1, buffer} = DataBuffer.take(buffer, 2)
      {t2, buffer} = DataBuffer.take(buffer, 2)
      {t3, buffer} = DataBuffer.take(buffer, 2)
      {t4, buffer} = DataBuffer.take(buffer, 3)

      assert IO.iodata_to_binary(t1) == "ab"
      assert IO.iodata_to_binary(t2) == "cd"
      assert IO.iodata_to_binary(t3) == "ef"
      assert IO.iodata_to_binary(t4) == "ghi"
      assert DataBuffer.empty?(buffer)
    end
  end

  describe "integration with typical MSS usage" do
    test "simulates TCP segmentation at MSS boundary" do
      mss = 10
      data = String.duplicate("x", 25)

      buffer = DataBuffer.new() |> DataBuffer.append(data)

      {seg1, buffer} = DataBuffer.take(buffer, mss)
      assert IO.iodata_length(seg1) == 10

      {seg2, buffer} = DataBuffer.take(buffer, mss)
      assert IO.iodata_length(seg2) == 10

      {seg3, buffer} = DataBuffer.take(buffer, mss)
      assert IO.iodata_length(seg3) == 5

      assert DataBuffer.empty?(buffer)
    end
  end
end
