# Multi-Command CLI with CliMate

This example demonstrates how to implement a multi-command CLI using CliMate, even though CliMate doesn't natively support subcommands.

## Overview

CliMate is designed for single-command applications, but you can implement multi-command CLIs by:

1. **Manual command parsing**: Parse the first argument as the command name
2. **Separate argument parsing**: Use CliMate's `parse_or_halt!/2` for each subcommand
3. **Command routing**: Route to appropriate handler functions

## Implementation Approaches

### Approach 1: Simple Command Routing

```elixir
def run(argv) do
  case argv do
    [] -> halt_error("No command specified")
    [command | args] ->
      case command do
        "ls" -> handle_ls(args)
        "cat" -> handle_cat(args)
        _ -> halt_error("Unknown command: #{command}")
      end
  end
end
```

### Approach 2: Structured Command Registry

```elixir
@commands %{
  "ls" => %{
    description: "List directory contents",
    handler: &handle_ls/1,
    help: "Usage: ls [OPTIONS] [PATH]..."
  }
}
```

## Key Features

### 1. Command-Specific Argument Parsing

Each subcommand can have its own argument specification:

```elixir
defp handle_ls(argv) do
  command = [
    options: [
      long: [type: :boolean, short: "l"],
      all: [type: :boolean, short: "a"]
    ],
    arguments: [path: [type: :string, default: "."]]
  ]
  
  %{options: opts, arguments: args} = parse_or_halt!(argv, command)
  # ... handle the command
end
```

### 2. Help System

Each command can have its own help text:

```elixir
if opts.help do
  writeln("""
  Usage: ls [OPTIONS] [PATH]
  
  Options:
    -l, --long    Use long listing format
    -a, --all     Show hidden files
  """)
  halt_success()
end
```

### 3. Global Help

Show available commands when no command is specified:

```elixir
defp show_global_help do
  writeln("""
  Available commands:
    ls    List directory contents
    cat   Concatenate files
    grep  Search for patterns
  """)
  halt_success()
end
```

## Usage Examples

```bash
# Show global help
./p11ex_cli

# Show command-specific help
./p11ex_cli ls --help

# Use commands with arguments
./p11ex_cli ls -la /path/to/dir
./p11ex_cli cat -n file1.txt file2.txt
./p11ex_cli grep -i "pattern" file.txt
```

## Advantages of This Approach

1. **Flexibility**: Each command can have completely different argument structures
2. **Maintainability**: Easy to add new commands by updating the command registry
3. **User Experience**: Familiar command-line interface similar to git, docker, etc.
4. **Help System**: Comprehensive help for both global and command-specific usage

## Limitations

1. **No native subcommand support**: CliMate doesn't understand subcommands natively
2. **Manual parsing**: You need to handle command routing yourself
3. **No automatic help generation**: Help text must be written manually

## Alternative Libraries

If you need more sophisticated subcommand support, consider:

- **OptionParser**: Elixir's built-in argument parser (more manual work)
- **ExCLI**: More feature-rich CLI library with subcommand support
- **Sage**: Another CLI library with subcommand capabilities

## Testing

You can test the CLI by running:

```bash
cd test_apps/p11ex_cli
mix run -e "P11exCli.CLI.run(System.argv())" -- ls -la
mix run -e "P11exCli.CLI.run(System.argv())" -- cat --help
```

This approach gives you the flexibility to create sophisticated multi-command CLIs while still leveraging CliMate's excellent argument parsing capabilities for each individual command. 
