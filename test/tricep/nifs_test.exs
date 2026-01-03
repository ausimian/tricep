defmodule Tricep.NifsTest do
  use ExUnit.Case, async: true

  alias Tricep.Nifs

  describe "checksum/1" do
    test "checksums flat binary" do
      # <<1, 2, 3, 4>> = 0x0102 + 0x0304 = 0x0406, ~0x0406 = 0xFBF9
      assert Nifs.checksum(<<1, 2, 3, 4>>) == 0xFBF9
    end

    test "checksums binary list without nesting" do
      # [<<1, 2>>, <<3, 4>>] should equal <<1, 2, 3, 4>>
      assert Nifs.checksum([<<1, 2>>, <<3, 4>>]) == Nifs.checksum(<<1, 2, 3, 4>>)
    end

    test "checksums nested lists" do
      # [[<<1>>, 2], <<3, 4>>] should equal <<1, 2, 3, 4>>
      assert Nifs.checksum([[<<1>>, 2], <<3, 4>>]) == Nifs.checksum(<<1, 2, 3, 4>>)
    end

    test "checksums mixed iodata" do
      # [<<1, 2, 3>>, 4, 5, <<6>>] should equal <<1, 2, 3, 4, 5, 6>>
      assert Nifs.checksum([<<1, 2, 3>>, 4, 5, <<6>>]) == Nifs.checksum(<<1, 2, 3, 4, 5, 6>>)
    end

    test "checksums odd-length binary" do
      # <<1, 2, 3>> = 0x0102 + 0x0300 = 0x0402, ~0x0402 = 0xFBFD
      assert Nifs.checksum(<<1, 2, 3>>) == 0xFBFD
    end

    test "checksums empty binary" do
      # Empty = sum of 0, ~0 = 0xFFFF
      assert Nifs.checksum(<<>>) == 0xFFFF
    end

    test "checksums empty list" do
      assert Nifs.checksum([]) == 0xFFFF
    end

    test "checksums with odd-length fragments" do
      # [<<1, 2, 3>>, <<4, 5>>] - fragments don't align to 16-bit boundaries
      # Should equal <<1, 2, 3, 4, 5>>
      assert Nifs.checksum([<<1, 2, 3>>, <<4, 5>>]) == Nifs.checksum(<<1, 2, 3, 4, 5>>)
    end

    test "handles deeply nested iodata" do
      nested = [[[[<<1, 2>>]], 3], [4, [[<<5, 6>>]]]]
      assert Nifs.checksum(nested) == Nifs.checksum(<<1, 2, 3, 4, 5, 6>>)
    end

    test "handles integer bytes" do
      assert Nifs.checksum([1, 2, 3, 4]) == Nifs.checksum(<<1, 2, 3, 4>>)
    end

    test "raises on invalid integer (>255)" do
      assert_raise ArgumentError, fn ->
        Nifs.checksum([256])
      end
    end

    test "raises on invalid integer (<0)" do
      assert_raise ArgumentError, fn ->
        Nifs.checksum([-1])
      end
    end

    test "known checksum value for zeros" do
      # Two zero bytes: sum = 0, ~0 = 0xFFFF
      assert Nifs.checksum(<<0, 0>>) == 0xFFFF
    end

    test "known checksum value for 0xFFFF" do
      # 0xFFFF: sum = 0xFFFF, ~0xFFFF = 0
      assert Nifs.checksum(<<0xFF, 0xFF>>) == 0
    end
  end
end
