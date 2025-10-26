
defmodule P11exCli.MixProject do
  use Mix.Project

  def project do
    [
      app: :p11ex_cli,
      version: "0.1.0",
      elixir: "~> 1.14",
      deps: deps(),
      escript: escript_config(),
      test_coverage: [tool: ExCoveralls],
    ]
  end

  def cli do
    [preferred_cli_env: [
      coveralls: :test,
      "coveralls.detail": :test,
      "coveralls.post": :test,
      "coveralls.html": :test,
      "coveralls.github": :test]]
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
      {:cli_mate, "== 0.8.4"},
      {:jason, "~> 1.4"},
      {:poolboy, "~> 1.5.2"},

      {:junit_formatter, "~> 3.3", only: :test},
      {:excoveralls, "~> 0.18", only: :test},
      {:jsonpath_ex, "~> 0.1.0", only: :test}
    ]
  end
end
