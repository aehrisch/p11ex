defmodule P11exCli.CLI do
  use ExCLI.DSL, escript: true

  name "p11ex"
  description "PKCS#11 command line tool"
  long_description "PKCS#11 command line tool"

  option :module,
    help: "Path to PKCS#11 module",
    type: :string

  command :list_slots do
    aliases ["slots"]
    description "List all PKCS#11 slots"

    run context do
      load_module(context)
      case P11ex.Module.list_slots(false) do
        {:ok, slots} ->
          IO.puts("Found #{length(slots)} slots:\n")
          print_slots(slots)
          System.halt(0)
        {:error, reason, details} ->
          IO.puts("Error listing slots: #{inspect(reason)}")
          IO.puts("Details: #{inspect(details)}")
          System.halt(1)
      end
    end
  end

  defp load_module(context) do
    module = context[:module] || System.get_env("P11EX_MODULE")
    if module do
      IO.puts("Using module: #{module}")
      case P11ex.Module.start_link(module) do
        {:ok, _module_pid} ->
          IO.puts("Module loaded successfully")
        {:error, reason} ->
          IO.puts("Error loading module: #{inspect(reason)}")
          System.halt(1)
      end
    else
      IO.puts("No module specified (use --module or set P11EX_MODULE), exiting")
      System.halt(1)
    end
  end

  defp print_slots(slots) do
    Enum.each(slots, fn slot ->
      IO.puts("Slot #{slot.slot_id}:")
      IO.puts("  Description: #{slot.description}")
      IO.puts("  Manufacturer: #{slot.manufacturer_id}")
      IO.puts("  Flags: #{inspect(slot.flags)}")
      IO.puts("  Hardware Version: #{inspect(slot.hardware_version)}")
      IO.puts("  Firmware Version: #{inspect(slot.firmware_version)}")
      case P11ex.Module.token_info(slot.slot_id) do
        {:ok, token_info} ->
          IO.puts("  Token Info:")
          IO.puts("    Label: #{token_info.label}")
          IO.puts("    Manufacturer: #{token_info.manufacturer_id}")
          IO.puts("    Model: #{token_info.model}")
          IO.puts("    Serial Number: #{token_info.serial_number}")
          IO.puts("    Flags: #{inspect(MapSet.to_list(token_info.flags))}")
          IO.puts("    Hardware Version: #{inspect(token_info.hardware_version)}")
          IO.puts("    Firmware Version: #{inspect(token_info.firmware_version)}")
        {:error, reason} ->
          IO.puts("  Error getting token info: #{inspect(reason)}")
      end
      IO.puts("\n")
    end)
  end

end
