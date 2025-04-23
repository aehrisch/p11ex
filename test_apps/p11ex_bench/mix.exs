defmodule P11ExBench.MixProject do
  use Mix.Project

  def project do
    [
      app: :p11ex_bench,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {P11exBench.Application, []}
    ]
  end

  defp deps do
    [
      {:p11ex, path: "../.."},
      {:plug_cowboy, "~> 2.6"},
      {:jason, "~> 1.4"},
      {:poolboy, "~> 1.5.2"}
    ]
  end
end
