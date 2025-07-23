
defmodule P11exCli.MixProject do
  use Mix.Project

  def project do
    [
      app: :p11ex_cli,
      version: "0.1.0",
      elixir: "~> 1.14",
      deps: deps(),
      escript: escript_config()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :p11ex]
    ]
  end

  defp escript_config do
    [
      name: "p11ex_cli",
      main_module: P11exCli
    ]
  end

  defp deps do
    [
      {:p11ex, path: "../.."},
      {:cli_mate, "== 0.8.1"},
      {:jason, "~> 1.4"}
    ]
  end
end
