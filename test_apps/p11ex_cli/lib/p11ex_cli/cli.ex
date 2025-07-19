defmodule P11exCli do
  def main([subcommand | rest]) do
    :code.add_patha('_build/dev/lib/p11ex/ebin')
    Application.ensure_all_started(:p11ex)
    case subcommand do
      "help" -> P11exCli.Help.main(rest)
      "list-slots" -> P11exCli.SlotList.main(rest)
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
    IO.puts("Available subcommands: help, list-slots, convert, token, key")
    IO.puts("Use 'p11ex help <subcommand>' for detailed help")
  end
end

# Help subcommand
defmodule P11exCli.Help do
  alias CliMate.CLI

  @command name: "p11ex help", module: __MODULE__,
    options: [],
    arguments: [subcommand: [type: :string, doc: "Subcommand to get help for"]]

  def main(args) do
    %{arguments: args} = CLI.parse_or_halt!(args, @command)
    show_help(args.subcommand)
  end

  defp show_help(subcommand) do
    case subcommand do
      "list-slots" -> P11exCli.SlotList.format_usage()
      _ ->
        IO.puts("Unknown subcommand: #{subcommand}")
        IO.puts("Available subcommands: convert, token, key, list-slots")
    end
  end
end
