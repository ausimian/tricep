defmodule Tricep.MixProject do
  use Mix.Project

  def project do
    [
      app: :tricep,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      compilers: [:elixir_make] ++ Mix.compilers(),
      make_targets: ["all"],
      make_clean: ["clean"],
      deps: deps()
    ]
  end

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
