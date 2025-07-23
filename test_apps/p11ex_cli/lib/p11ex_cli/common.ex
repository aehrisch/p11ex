defmodule P11exCli.Common do
  alias CliMate.CLI

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

  def really_load_module(module, verbose) do
    case P11ex.Module.start_link(module) do
      {:ok, module_pid} ->
        if verbose do
          IO.puts("Loaded module #{module} (pid #{inspect(module_pid)})")
        end
        module_pid
      {:error, reason} ->
        IO.puts("Error loading module: #{reason}")
        System.halt(1)
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
        System.halt(1)
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
          System.halt(2)
      end
    else
      if System.get_env("P11EX_PIN") do
        System.get_env("P11EX_PIN")
      else
        IO.puts("No PIN specified, and P11EX_PIN is not set")
        System.halt(2)
      end
    end
  end

  def find_slot_by_label!(module, options) do
    label = Map.get(options, :token_label)
    case label do
      nil ->
        IO.puts("No token label specified")
        System.halt(2)
      _ ->
        case P11ex.Module.find_slot_by_tokenlabel(label) do
          {:ok, slot} ->
            slot
          {:error, reason} ->
            IO.puts("Error finding slot by label: #{inspect(reason)}")
            System.halt(1)
        end
    end
  end

  def login!(slot, options) do
    pin = get_pin!(options)

    with {:ok, session_pid} <- P11ex.Session.start_link([module: P11ex.Module, slot_id: slot.slot_id, flags: [:rw_session]]),
         :ok <- P11ex.Session.login(session_pid, :user, pin) do
      {:ok, session_pid}
    else
      {:error, reason} ->
        IO.puts("Error logging in: #{inspect(reason)}")
        System.halt(1)
    end
  end

  def check_output_format!(options) do
    case Map.get(options, :output_format) do
      "json" -> :json
      "text" -> :text
      _ ->
        IO.puts("Invalid output format: #{inspect(options.output_format)}")
        System.halt(2)
    end
  end

  def attrib_value_to_str(v) when is_binary(v) do
    Base.encode16(v)
  end

  def attrib_value_to_str(v) do
    inspect(v)
  end

end
