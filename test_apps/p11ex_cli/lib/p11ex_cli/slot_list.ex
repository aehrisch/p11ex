defmodule P11exCli.SlotList do
  alias CliMate.CLI

  @command name: "p11ex list-slots",
    module: __MODULE__,
    options: P11exCli.Common.options() ++ [
      with_token: [
        short: :t,
        type: :boolean,
        default: true,
        doc: "List only slots that contain a token."
      ]
    ],
    arguments: []
  def main(args) do
    res = CLI.parse_or_halt!(args, @command)
    module = P11exCli.Common.load_module(res.options)

    case P11ex.Module.list_slots(res.options.with_token) do
      {:ok, slots} ->
        Enum.each(slots, fn s ->
          print_slot(s)
          case P11ex.Module.token_info(s) do
            {:ok, token_info} ->
              print_token_info(token_info)
            {:error, reason} ->
              IO.puts("Error getting token info: #{reason}")
          end
          IO.puts("")
        end)
      {:error, reason} ->
        IO.puts("Error listing slots: #{reason}")
    end
  end

  def format_usage do
    IO.puts(CLI.format_usage(@command))
  end

  defp print_slot(slot) do
    IO.puts("Slot #{slot.slot_id}:")
    IO.puts("  Description: #{slot.description}")
    IO.puts("  Manufacturer: #{slot.manufacturer_id}")
    IO.puts("  Hardware Version: #{version(slot.hardware_version)}")
    IO.puts("  Firmware Version: #{version(slot.firmware_version)}")
    IO.puts("  Flags: #{inspect(slot.flags)}")
  end

  defp version(t) do
    case t do
      {major, minor} ->
        "#{major}.#{minor}"
      _ ->
        inspect(t)
    end
  end

  defp print_token_info(token_info) do
    IO.puts("  Token Info:")
    IO.puts("    Label: #{token_info.label}")
    IO.puts("    Manufacturer: #{token_info.manufacturer_id}")
    IO.puts("    Model: #{token_info.model}")
    IO.puts("    Serial Number: #{token_info.serial_number}")
    IO.puts("    Hardware Version: #{version(token_info.hardware_version)}")
    IO.puts("    Firmware Version: #{version(token_info.firmware_version)}")
    IO.puts("    Min. PIN Length: #{token_info.min_pin_len}")
    IO.puts("    Max. PIN Length: #{token_info.max_pin_len}")
    IO.puts("    Max. Session Count: #{token_info.max_session_count}")
    IO.puts("    Session Count: #{token_info.session_count}")
    IO.puts("    Max. R/W Session Count: #{token_info.max_rw_session_count}")
    IO.puts("    Session R/W Count: #{token_info.rw_session_count}")
    IO.puts("    Total Private Memory: #{token_info.total_private_memory}")
    IO.puts("    Free Private Memory: #{token_info.free_private_memory}")
    IO.puts("    Total Public Memory: #{token_info.total_public_memory}")
    IO.puts("    Free Public Memory: #{token_info.free_public_memory}")
    IO.puts("    UTC Time: #{token_info.utc_time}")
    IO.puts("    Flags: #{inspect(token_info.flags)}")
  end

end
