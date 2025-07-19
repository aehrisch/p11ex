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
    tokenlabel: [
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

  def options do
    @options
  end

  def token_options do
    @token_options
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

end
