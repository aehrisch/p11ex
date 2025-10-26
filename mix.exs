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
      erlc_paths: ["src"],
      asn1_options: asn1_options(),
      compilers: [:asn1, :elixir_make] ++ Mix.compilers(),
      make_clean: ["clean"],
      make_targets: ["all"],
      # Hex.pm package configuration
      package: package(),
      description: "PKCS#11 interface for Elixir",
      # Documentation configuration
      docs: docs()
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

  defp asn1_options, do: [maps: true, der: true, jer: false, verbose: true]

  defp package do
    [
      name: "p11ex",
      files: ~w(lib src mix.exs README.md LICENSE),
      maintainers: ["Eric Knauel"],
      licenses: ["BSD-3-Clause"],
      links: %{
        "GitHub" => "https://github.com/aehrisch/p11ex",
        "Documentation" => "https://hexdocs.pm/p11ex",
        "Changelog" => "https://hexdocs.pm/p11ex/changelog.html"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      name: "P11ex",
      source_url: "https://github.com/aehrisch/p11ex",
      homepage_url: "https://github.com/aehrisch/p11ex",
      extras: [
        "README.md",
        "test_apps/p11ex_cli/CLI_DOCUMENTATION.md": [title: "CLI Tool Documentation"],
        "CHANGELOG.md": [title: "Changelog"]
      ],
      groups_for_modules: [
        "Core Modules": [
          P11ex,
          P11ex.Module,
          P11ex.Session
        ],
        "Data Structures": [
          P11ex.Lib,
          P11ex.Lib.Slot,
          P11ex.Lib.SessionHandle,
          P11ex.Lib.ObjectHandle,
          P11ex.Lib.ObjectAttributes,
          P11ex.Lib.ModuleHandle
        ],
        "Flags and Parameters": [
          P11ex.Flags,
          P11ex.ECParam
        ]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :asn1]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:poolboy, "~> 1.5.2"},

      {:elixir_make, "~> 0.7", runtime: false},
      {:asn1_compiler, "~> 0.1", runtime: false},

      {:junit_formatter, "~> 3.3", only: :test},
      {:excoveralls, "~> 0.18", only: :test},
      {:ex_doc, "~> 0.34", only: [:dev, :test]},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end


end
