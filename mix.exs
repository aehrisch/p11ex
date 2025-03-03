defmodule P11ex.MixProject do
  use Mix.Project

  def project do
    [
      app: :p11ex,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      compilers: [:elixir_make] ++ Mix.compilers(),
      make_clean: ["clean"],
      make_targets: ["all"]

    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:elixir_make, "~> 0.7", runtime: false},

      {:junit_formatter, "~> 3.3", only: :test},
      {:excoveralls, "~> 0.18", only: :test}
    ]
  end
end
