defmodule Tricep.AddressTest do
  use ExUnit.Case, async: true

  alias Tricep.Address

  describe "to_bytes/1" do
    test "converts IPv6 tuple to 16-byte binary" do
      addr = {0x2001, 0x0DB8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001}
      expected = <<0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01>>

      assert Address.to_bytes(addr) == expected
    end

    test "converts loopback address" do
      addr = {0, 0, 0, 0, 0, 0, 0, 1}
      expected = <<0::120, 1::8>>

      assert Address.to_bytes(addr) == expected
    end

    test "converts all-zeros address" do
      addr = {0, 0, 0, 0, 0, 0, 0, 0}
      expected = <<0::128>>

      assert Address.to_bytes(addr) == expected
    end

    test "converts link-local address" do
      addr = {0xFE80, 0, 0, 0, 0, 0, 0, 0x0001}
      expected = <<0xFE, 0x80, 0::104, 0x01>>

      assert Address.to_bytes(addr) == expected
    end
  end

  describe "from/1 with string" do
    test "parses full IPv6 address string" do
      {:ok, result} = Address.from("2001:db8::1")
      expected = <<0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01>>

      assert result == expected
    end

    test "parses loopback address string" do
      {:ok, result} = Address.from("::1")
      expected = <<0::120, 1::8>>

      assert result == expected
    end

    test "parses link-local address string" do
      {:ok, result} = Address.from("fe80::1")
      expected = <<0xFE, 0x80, 0::104, 0x01>>

      assert result == expected
    end

    test "parses fully expanded address" do
      {:ok, result} = Address.from("2001:0db8:0000:0000:0000:0000:0000:0001")
      expected = <<0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01>>

      assert result == expected
    end

    test "returns error for invalid address" do
      assert {:error, :einval} = Address.from("not-an-address")
    end

    test "returns error for IPv4 address" do
      assert {:error, :einval} = Address.from("192.168.1.1")
    end
  end

  describe "from/1 with tuple" do
    test "converts tuple to binary" do
      addr = {0x2001, 0x0DB8, 0, 0, 0, 0, 0, 0x0001}
      {:ok, result} = Address.from(addr)
      expected = <<0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01>>

      assert result == expected
    end
  end
end
