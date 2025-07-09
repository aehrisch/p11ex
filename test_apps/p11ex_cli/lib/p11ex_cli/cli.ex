defmodule P11exCli.CLI do
  use ExCLI.DSL, escript: true

  name "p11ex"
  description "PKCS#11 command line tool"
  long_description "PKCS#11 command line tool"

  # Public process functions for ExCLI
  def validate_password_source(_arg, context, args) do
    value = context[:password_source]
    cond do
      is_nil(value) ->
        {:ok, context, args}
      value == "" ->
        {:error, :invalid_password_source, "Password source cannot be empty"}
      value in ["file", "env", "stdin", "tty"] ->
        {:ok, context, args}
      true ->
        {:error, :invalid_password_source, "Password source must be one of: file, env, stdin, tty. Got: #{inspect(value)}"}
    end
  end

  def validate_slot_id(_arg, context, args) do
    value = context[:slot_id]
    if is_integer(value) and value >= 0 do
      {:ok, context, args}
    else
      {:error, :invalid_slot_id, "Slot ID must be a non-negative integer. Got: #{value}"}
    end
  end

  def validate_object_class(_arg, context, args) do
    value = context[:object_class]
    case value do
      "pubk" ->
        {:ok, Map.put(context, :object_class, :cko_public_key), args}
      "prvk" ->
        {:ok, Map.put(context, :object_class, :cko_private_key), args}
      "seck" ->
        {:ok, Map.put(context, :object_class, :cko_secret_key), args}
      _ ->
        {:error, :invalid_object_class, "Object class must be one of: pubk, prvk, seck. Got: #{value}"}
    end
  end

  option :module,
    help: "Path to PKCS#11 module",
    type: :string

  option :password_source,
    help: "Source for password input (file, env, stdin, tty), default: tty",
    type: :string,
    default: "tty",
    process: &__MODULE__.validate_password_source/3

  option :password_file,
    help: "File containing password (used when password-source is 'file')",
    type: :string

  option :token_label,
    help: "Label of the token to use",
    type: :string

  option :slot_id,
    help: "Slot ID (non-negative integer)",
    type: :integer,
    process: &__MODULE__.validate_slot_id/3

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

  command :list_objects do
    aliases ["objects"]
    description "List objects in a token"
    argument :object_class, required: true, process: &__MODULE__.validate_object_class/3

    run context do
      module = load_module(context)
      object_class = context[:object_class]

      session = open_session!(context)

      IO.puts("Listing #{object_class} objects...")
      objects = P11ex.Session.find_objects(session,
        [{:cka_class, object_class}, {:cka_token, true}], 10)

      IO.inspect(label: "############ objects")

      System.halt(0)
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

  defp open_session!(context) do
    slot = find_slot!(context)
    password = get_password!(context, context[:password_source])
    session = case P11ex.Session.start_link(module: P11ex.Module, slot_id: slot.slot_id, password: password) do
      {:ok, session} -> session
      {:error, reason} ->
        IO.puts("Error opening session: #{inspect(reason)}")
        System.halt(1)
    end
    IO.inspect(session, label: "############ session")
    case P11ex.Session.login(session, :user, password) do
      :ok ->
        IO.puts("Logged in to slot #{slot.slot_id}")
        session
      {:error, reason} ->
        IO.puts("Error logging in: #{inspect(reason)}")
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

  defp find_slot!(context) do
    case P11ex.Module.list_slots(true) do
      {:ok, slots} ->
        filter_slots(context, slots)
      {:error, reason} ->
        IO.puts("Error listing slots: #{inspect(reason)}")
        System.halt(1)
    end
  end

  defp filter_slots(context, slots) do
    if context[:slot_id] do
      Enum.find(slots, fn slot -> slot.slot_id == context[:slot_id] end)
    else
      if context[:token_label] do
        Enum.find(slots, fn slot ->
          {:ok, token_info} = P11ex.Module.token_info(slot.slot_id)
          token_info.label == context[:token_label]
        end)
      else
        IO.puts("No slot or token label specified, exiting")
        System.halt(1)
      end
    end
  end

  defp get_password!(context, password_source) do
    # Since ExCLI seems to have issues with option parsing, prioritize environment variable
    env_source = System.get_env("P11EX_PASSWORD_SOURCE")
    actual_source = env_source || password_source || "tty"
    get_password_by_source!(context, actual_source)
  end

  defp get_password_by_source!(_context, "env") do
    case System.get_env("P11EX_PASSWORD") do
      nil ->
        IO.puts("failed to get password: P11EX_PASSWORD environment variable is not set")
        System.halt(1)
      password -> password
    end
  end

  defp get_password_by_source!(context, "file") do
    case context[:password_file] do
      nil ->
        IO.puts("failed to get password: password file is not set, use --password-file to set it")
        System.halt(1)
      file -> File.read!(file) |> String.slice(0, 1024)
    end
  end

  defp get_password_by_source!(_context, "stdin") do
    IO.gets("Enter password: ") |> String.trim()
  end

  defp get_password_by_source!(_context, "tty") do
    case :io.getopts() do
      {:ok, opts} ->
        if opts[:binary] do
          IO.gets("Enter password: ") |> String.trim()
        else
          IO.puts("Stdin is not a terminal, cannot use tty password source")
          System.halt(1)
        end
      _ ->
        IO.puts("Cannot determine terminal status, cannot use tty password source")
        System.halt(1)
    end
  end

end
