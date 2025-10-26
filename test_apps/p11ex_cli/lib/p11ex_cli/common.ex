defmodule P11exCli.Common do

  defp exit, do: Application.fetch_env!(:p11ex_cli, :exit_mod)

  @options [
    verbose: [
      short: :v,
      type: :boolean,
      default: false,
      doc: "Output verbose information"
    ],
    module: [
      short: :m,
      type: :string,
      required: false,
      doc: "Path to PKCS#11 module file"
    ]
  ]

  @token_options [
    token_label: [
      short: :l,
      type: :string,
      required: false,
      doc: "Token label to use"
    ],
    pin_file: [
      type: :string,
      required: false,
      doc: "PIN file to use"
    ]
  ]

  @output_options [
    output_format: [
      short: :f,
      type: :string,
      required: false,
      default: "text",
      doc: "Output format (json, text)."
    ]
  ]

  def options do
    @options
  end

  def token_options do
    @token_options
  end

  def output_options do
    @output_options
  end

  @doc """
  Load the module and return the pid.
  If the module is already loaded, return the pid.
  If the module is not loaded, start it and return the pid.
  If the module fails to load, exit with an error.
  """
  @spec really_load_module(String.t(), boolean()) :: pid()
  def really_load_module(module, verbose) do
    # First check if P11ex.Module is already running
    case Process.whereis(P11ex.Module) do
      nil ->
        # Not running, try to start it
        case P11ex.Module.start_link(module) do
          {:ok, module_pid} ->
            # Unlink so it doesn't terminate when our process (e.g. test) exits
            # This allows the singleton to persist across multiple CLI invocations/tests
            Process.unlink(module_pid)
            if verbose do
              IO.puts("Loaded module #{module} (pid #{inspect(module_pid)})")
            end
            module_pid
          {:error, {:already_started, pid}} ->
            # Race condition: started between whereis and start_link
            if verbose do
              IO.puts("Module #{module} already loaded (pid #{inspect(pid)})")
            end
            pid
          {:error, reason} ->
            IO.puts("Error loading module: #{inspect(reason)}")
            exit().halt(:error)
        end
      pid ->
        # Already running
        if verbose do
          IO.puts("Module #{module} already loaded (pid #{inspect(pid)})")
        end
        pid
    end
  end


  def load_module(options) do
    verbose = verbose?(options)
    module_from_options = Map.get(options, :module)
    if module_from_options do
      really_load_module(module_from_options, verbose)
    else
      if System.get_env("P11EX_MODULE") do
        really_load_module(System.get_env("P11EX_MODULE"), verbose)
      else
        IO.puts("No module specified, and P11EX_MODULE is not set")
        exit().halt(:error)
      end
    end
  end

  def verbose?(options) do
    Map.get(options, :verbose, false)
  end

  def get_pin!(options) do
    pin_file = Map.get(options, :pin_file)
    if pin_file do
      case File.read(pin_file) do
        {:ok, pin} ->
          pin
        {:error, reason} ->
          IO.puts("Error reading PIN file: #{reason}")
          exit().halt(:invalid_param)
      end
    else
      if System.get_env("P11EX_PIN") do
        System.get_env("P11EX_PIN")
      else
        IO.puts("No PIN specified, and P11EX_PIN is not set")
        exit().halt(:invalid_param)
      end
    end
  end

  def find_slot_by_label!(options) do
    label = Map.get(options, :token_label) || System.get_env("P11EX_TOKEN_LABEL")
    case label do
      nil ->
        IO.puts("No token label specified")
        exit().halt(:invalid_param)
      _ ->
        case P11ex.Module.find_slot_by_tokenlabel(label) do
          {:ok, nil} ->
            IO.puts("No slot found with token label: #{label}")
            exit().halt(:error)
          {:ok, %P11ex.Lib.Slot{} = slot} ->
            IO.puts("Found slot by label: #{slot.description}")
            slot
          {:error, reason} ->
            IO.puts("Error finding slot by label: #{inspect(reason)}")
            exit().halt(:error)
        end
    end
  end

  def login!(slot = %P11ex.Lib.Slot{}, options) do
    pin = get_pin!(options)

    # Workaround: If the module was previously logged out, login_type might be nil
    # Reset it to false to avoid case clause errors in P11ex.Session
    if P11ex.Module.login_type() == nil do
      P11ex.Module.register_login(false)
    end

    with {:ok, session_pid} <- P11ex.Session.start_link([module: P11ex.Module, slot_id: slot.slot_id, flags: [:rw_session]]),
         :ok <- P11ex.Session.login(session_pid, :user, pin) do
      {:ok, session_pid}
    else
      {:error, reason} ->
        IO.puts("Error logging in: #{inspect(reason)}")
        exit().halt(:error)
    end
  end

  def check_output_format!(options) do
    case Map.get(options, :output_format) do
      "json" -> :json
      "text" -> :text
      _ ->
        IO.puts("Invalid output format: #{inspect(options.output_format)}")
        exit().halt(:invalid_param)
    end
  end

  def attrib_value_to_str(v) when is_binary(v) do
    if printable_ascii?(v) do
      "0x" <> Base.encode16(v) <> " [" <> v <> "]"
    else
      "0x" <> Base.encode16(v)
    end
  end

  def attrib_value_to_str(v) do
    inspect(v)
  end

  defp printable_ascii?(binary) do
    binary
    |> :binary.bin_to_list()
    |> Enum.all?(fn byte -> byte >= 32 and byte <= 126 end)
  end

  def attrib_for_ref(ref_str) do
    cond do
      String.match?(ref_str, ~r/^label:/) ->
        {:cka_label, String.slice(ref_str, 6..-1//1)}

      String.match?(ref_str, ~r/^id:[[:xdigit:]]+/i) ->
        case Base.decode16(String.slice(ref_str, 3..-1//1), case: :mixed) do
          {:ok, id_bin} ->
            {:cka_id, id_bin}
          {:error, _} ->
            {:error, "Invalid ID format"}
        end

      String.match?(ref_str, ~r/^handle:[[:digit:]]+/) ->
        case Integer.parse(String.slice(ref_str, 7..-1//1)) do
          {handle, ""} ->
            {:cka_handle, handle}
          _ ->
            {:error, "Invalid handle format"}
        end

      true ->
        {:error, "Invalid reference format"}
    end
  end

  @doc """
  Find a key by reference string (label:name, id:hexstring, or handle:number).
  Returns the ObjectHandle or halts with an error.
  """
  def find_key_by_ref!(session_pid, ref_str, object_class) do
    with {:ok, key} <- find_key_by_ref(session_pid, ref_str, object_class) do
      key
    else
      {:error, msg} ->
        IO.puts(msg)
        exit().halt(:invalid_param)
    end
  end

  def find_key_by_ref(session_pid, ref_str, object_class) do
    case attrib_for_ref(ref_str) do
      {:error, msg} ->
        {:error, "Error parsing key reference: #{msg}"}

      {:cka_handle, handle} ->
        # For handle references, we don't need to search
        %P11ex.Lib.ObjectHandle{
          session: nil,  # Will be set by Session if needed
          handle: handle
        }

      search_attrib ->
        # Search for the key
        search_attribs = [search_attrib, {:cka_class, object_class}]
        case P11ex.Session.find_objects(session_pid, search_attribs, 10) do
          {:ok, []} ->
            {:error, "Key not found with reference: #{ref_str}"}
          {:ok, [key | _]} ->
            {:ok, key}
          {:ok, keys} when length(keys) > 1 ->
            IO.puts("Warning: Multiple keys found with reference: #{ref_str}, using the first one")
            {:ok, hd(keys)}
          {:error, reason} ->
            {:error, "Error finding key: #{inspect(reason)}"}
        end
    end
  end

  @doc """
  Find a key by reference, trying multiple object classes.
  """
  def find_key_by_ref_any_class!(session_pid, ref_str, classes) do
    case attrib_for_ref(ref_str) do
      {:error, msg} ->
        IO.puts("Error parsing key reference: #{msg}")
        exit().halt(:invalid_param)

      {:cka_handle, handle} ->
        %P11ex.Lib.ObjectHandle{
          session: nil,
          handle: handle
        }

      search_attrib ->
        # Try each class until we find a match
        result = Enum.find_value(classes, fn class ->
          search_attribs = [search_attrib, {:cka_class, class}]
          case P11ex.Session.find_objects(session_pid, search_attribs, 10) do
            {:ok, [key | _]} -> {:found, key}
            _ -> nil
          end
        end)

        case result do
          {:found, key} -> key
          nil ->
            IO.puts("Key not found with reference: #{ref_str}")
            exit().halt(:invalid_param)
        end
    end
  end

  @doc """
  Write wrapped key bytes to a file in the specified format.
  """
  def write_wrapped_key(file_path, wrapped_key_bytes, format) do
    data = case format do
      :binary -> wrapped_key_bytes
      :hex -> Base.encode16(wrapped_key_bytes, case: :lower)
      :base64 -> Base.encode64(wrapped_key_bytes)
    end

    case File.write(file_path, data) do
      :ok -> :ok
      {:error, reason} ->
        IO.puts("Error writing wrapped key to file: #{inspect(reason)}")
        exit().halt(:error)
    end
  end

  @doc """
  Read wrapped key bytes from a file in the specified format.
  """
  def read_wrapped_key(file_path, format) do
    case File.read(file_path) do
      {:ok, data} ->
        case format do
          :binary ->
            data
          :hex ->
            case Base.decode16(String.trim(data), case: :mixed) do
              {:ok, bytes} -> bytes
              {:error, _} ->
                IO.puts("Error: Invalid hex format in input file")
                exit().halt(:invalid_param)
            end
          :base64 ->
            case Base.decode64(String.trim(data)) do
              {:ok, bytes} -> bytes
              {:error, _} ->
                IO.puts("Error: Invalid base64 format in input file")
                exit().halt(:invalid_param)
            end
        end
      {:error, reason} ->
        IO.puts("Error reading wrapped key from file: #{inspect(reason)}")
        exit().halt(:error)
    end
  end

  @doc """
  Read the attributes of the object identified by object handle `object` one by one.
  For some token this is necessary because its unclear which attributes (or attribute
  types) are supported.
  """
  def carefully_read_object(session_pid, object, attributes) do
    attributes
    |> Enum.map(fn attribute ->
      case P11ex.Session.read_object(session_pid, object, MapSet.new([attribute])) do
        {:ok, attribs, _failed} -> {:ok, attribs}
        {:error, reason} -> {:error, reason}
      end
    end)
    |> Enum.filter(fn x ->
      case x do
        {:ok, _, _} -> false
        _ -> true
      end
    end)
  end

end
