defmodule Tricep.MixProject do
  use Mix.Project

  def project do
    [
      app: :tricep,
      version: "0.1.0",
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      compilers: [:elixir_make] ++ Mix.compilers(),
      make_targets: ["all"],
      make_clean: ["clean"],
      deps: deps(),
      test_coverage: [ignore_modules: [Tricep.IntegrationCase, Tricep.DummyLink]]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {Tricep.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:typedstruct, "~> 0.5", runtime: false},
      {:tundra, "~> 0.3.0"},
      {:elixir_make, "~> 0.9", runtime: false}
    ]
  end
end
