defmodule TricepTest do
  use ExUnit.Case
  doctest Tricep

  test "greets the world" do
    assert Tricep.hello() == :world
  end
end
