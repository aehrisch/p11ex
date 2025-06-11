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
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test,
        "coveralls.github": :test
      ],
      erlc_paths: ["src"],
      asn1_options: asn1_options(),
      compilers: [:asn1, :elixir_make] ++ Mix.compilers(),
      make_clean: ["clean"],
      make_targets: ["all"],
      # Hex.pm package configuration
      package: package(),
      description: "PKCS#11 interface for Elixir",
      licenses: ["BSD-3-Clause"],
      links: %{
        "GitHub" => "https://github.com/#{github_repo()}",
        "Documentation" => "https://hexdocs.pm/p11ex"
      },
      # git_ops configuration
      git_ops: [
        mix_tasks: [
          "git_ops.release",
          "git_ops.changelog"
        ],
        changelog: [
          # Conventional commit types and their corresponding changelog sections
          types: [
            feat: "Added",
            fix: "Fixed",
            docs: "Documentation",
            style: "Style",
            refactor: "Refactored",
            perf: "Performance",
            test: "Testing",
            chore: "Chores",
            breaking: "Breaking Changes"
          ],
          # Commit types that should trigger a version bump
          version_types: [
            feat: :minor,
            fix: :patch,
            breaking: :major
          ],
          # File to write the changelog to
          file: "CHANGELOG.md",
          # Template for the changelog
          template: """
          # Changelog

          All notable changes to this project will be documented in this file.

          The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
          and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

          {{changelog}}
          """
        ]
      ]
    ]
  end

  defp asn1_options, do: [maps: true, der: true, jer: false, verbose: true]

  defp github_repo do
    "eric/p11ex"
  end

  defp package do
    [
      name: "p11ex",
      files: ~w(lib src mix.exs README.md LICENSE CHANGELOG.md),
      maintainers: ["Eric"],
      licenses: ["BSD-3-Clause"]
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
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:git_ops, "~> 2.6", runtime: false}
    ]
  end


end
