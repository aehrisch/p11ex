defmodule P11exCli do


  @moduledoc """
  The main module for the p11ex CLI tool.
  """

  def main([subcommand | rest]) do
    :code.add_patha(~c"_build/dev/lib/p11ex/ebin")

    Logger.configure(level: :warning)

    Application.ensure_all_started(:p11ex)

    case subcommand do
      "help" -> P11exCli.Help.main(rest)
      "list-slots" -> P11exCli.SlotList.main(rest)
      "list-objects" -> P11exCli.ObjectList.main(rest)
      "key-gen-aes" -> P11exCli.KeyGenAes.main(rest)
      "key-wrap" -> P11exCli.KeyWrap.main(rest)
      "key-unwrap" -> P11exCli.KeyUnwrap.main(rest)
      "kcv-gen" -> P11exCli.KcvGen.main(rest)
      _ ->
        IO.puts("Unknown subcommand: #{subcommand}")
        print_usage()
    end
  end

  def main([]) do
    print_usage()
  end

  defp print_usage do
    IO.puts("Usage: p11ex <subcommand> [options]")
    IO.puts("Available subcommands: help, list-slots, list-objects, key-gen-aes, key-wrap, key-unwrap, kcv-gen")
    IO.puts("Use 'p11ex help <subcommand>' for detailed help")
  end
end

# Help subcommand
defmodule P11exCli.Help do
  alias CliMate.CLI

  defp exit, do: Application.fetch_env!(:p11ex_cli, :exit_mod)

  @command name: "p11ex help", module: __MODULE__,
    options: [],
    arguments: [subcommand: [type: :string, doc: "Subcommand to get help for"]]

  def main(args) do
    case CLI.parse(args, @command) do
      {:ok, %{arguments: args}} ->
        show_help(args.subcommand)
      {:error, reason} ->
        IO.puts("Error parsing arguments: #{inspect(reason)}")
        exit().halt(:invalid_param)
    end
  end

  defp show_help(subcommand) do
    case subcommand do
      "list-slots" -> P11exCli.SlotList.format_usage()
      "list-objects" -> P11exCli.ObjectList.format_usage()
      "key-gen-aes" -> P11exCli.KeyGenAes.format_usage()
      "key-wrap" -> P11exCli.KeyWrap.format_usage()
      "key-unwrap" -> P11exCli.KeyUnwrap.format_usage()
      "kcv-gen" -> P11exCli.KcvGen.format_usage()
      _ ->
        IO.puts("Unknown subcommand: #{subcommand}")
        IO.puts("Available subcommands: list-slots, list-objects, key-gen-aes, key-wrap, key-unwrap")
    end
  end
end
