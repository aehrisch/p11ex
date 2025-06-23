
defmodule P11exCli.MixProject do
  use Mix.Project

  def project do
    [
      app: :p11ex_cli,
      version: "0.1.0",
      elixir: "~> 1.14",
      escript: [
        main_module: P11exCli.CLI,
        name: "p11ex"
      ],
      deps: deps()
    ]
  end

  defp deps do
    [
      {:p11ex, path: "../.."},
      {:ex_cli, "~> 0.1.6"}
    ]
  end
end
