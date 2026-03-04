defmodule P11exCli.Sign do
  alias CliMate.CLI
  alias P11exCli.SignHelpers, as: SH

  require Logger

  defp exit, do: Application.fetch_env!(:p11ex_cli, :exit_mod)

  @command name: "p11ex sign",
    module: __MODULE__,
    options: P11exCli.Common.options() ++ P11exCli.Common.token_options() ++ [
      format: [
        short: :f,
        type: :string,
        required: false,
        default: "bin",
        doc: "Output format for signature (bin, hex, base64)"
      ]
    ],
    arguments: [
      sig_mechanism: [
        type: :string,
        required: true,
        doc: "Signing mechanism (e.g., rsa_pkcs_plain, rsa_pkcs_sha256, ecdsa_sha256)"
      ],
      digest_mechanism: [
        type: :string,
        required: true,
        doc: "Digest mechanism (e.g. none, sha256, sha384, sha512)"
      ],
      key_ref: [
        type: :string,
        required: true,
        doc: "Reference to private key (label:name, id:hex, or handle:number)"
      ],
      input_file: [
        type: :string,
        required: true,
        doc: "Path to input file"
      ],
      output_file: [
        type: :string,
        required: true,
        doc: "Path to output file"
      ]
    ]

  def main(args) do
    res = case CLI.parse(args, @command) do
      {:ok, res} ->
        res
      {:error, reason} ->
        IO.puts(:stderr, "Error parsing arguments: #{inspect(reason)}")
        exit().halt(:invalid_param)
    end

    # Parse output format
    output_format = SH.parse_format!(res.options.format)

    # Parse digest mechanism
    digest_mechanism = SH.parse_digest_mechanism!(res.arguments.digest_mechanism)
    Logger.debug("using digest mechanism: #{inspect(digest_mechanism)}")

    # Parse signature mechanism
    mechanism_info = SH.parse_sign_mechanism!(res.arguments.sig_mechanism, digest_mechanism)
    Logger.debug("using mechanism: #{inspect(mechanism_info)}")

    # Load module and login
    P11exCli.Common.load_module(res.options)
    slot = P11exCli.Common.find_slot_by_label!(res.options)
    {:ok, session_pid} = P11exCli.Common.login!(slot, res.options)

    # Find private key
    private_key = P11exCli.Common.find_key_by_ref!(
      session_pid,
      res.arguments.key_ref,
      :cko_private_key)

    input_file =
      if SH.mechanism_hashes_internally?(mechanism_info) do
        res.arguments.input_file
      else
        pre_hash_input_data(digest_mechanism, res.arguments.input_file, res.options.verbose)
      end

    # Perform signing
    signature_bytes = perform_signature!(
      session_pid,
      mechanism_info,
      private_key,
      input_file,
      res.options.verbose)

    formatted_signature = SH.format_signature(signature_bytes, mechanism_info, output_format)
    SH.write_output(res.arguments.output_file, formatted_signature)

    if res.options.verbose do
      IO.puts("Signature generated successfully (#{byte_size(signature_bytes)} bytes)")
    end

    P11ex.Session.logout(session_pid)
    exit().halt(:ok)
  end

  def pre_hash_input_data(nil, input_file, verbose) do
    if verbose do
      IO.puts("Using unhashed input data")
    end
    input_file
  end

  def pre_hash_input_data(hash_alg, input_file, verbose) do
    if verbose do
      IO.puts("Pre-hashing input data with #{hash_alg}...")
    end
    data = SH.read_input_data!(input_file)
    digest = :crypto.hash(hash_alg, data)
    temp_path = Path.join(System.tmp_dir!(), "p11ex_#{:erlang.unique_integer([:positive])}.bin")
    File.write!(temp_path, digest)
    File.close(temp_path)
    if verbose do
      IO.puts("Hashed input data written to #{temp_path}")
    end
    register_remove_on_exit(temp_path)
    temp_path
  end

  # Spawns a process linked to the current one; when this process exits, the file at path is deleted.
  defp register_remove_on_exit(path) do
    parent = self()
    spawn_link(fn ->
      Process.flag(:trap_exit, true)
      receive do
        {:EXIT, ^parent, _reason} -> File.rm(path)
      end
    end)
  end

  # Main signing logic
  defp perform_signature!(session_pid, mechanism, key, input_file, verbose) do

    data = SH.read_input_data!(input_file)

    with :ok <- P11ex.Session.sign_init(session_pid, mechanism, key),
         {:ok, signature} <- P11ex.Session.sign(session_pid, data) do
      if verbose do
        IO.puts("Signature generated successfully (#{byte_size(signature)} bytes)")
      end
      signature
    else err ->
      handle_error!("Error signing data", err)
      exit().halt(:error)
    end
  end


  def format_usage do
    IO.puts(CLI.format_usage(@command))
  end

  defp handle_error!(text, {:error, reason}), do: handle_error!(text, {:error, reason, nil})
  defp handle_error!(text, {:error, reason, details}) do
    IO.puts(:stderr, "#{text}: #{inspect(reason)} #{inspect(details)}")
    exit().halt(:error)
  end
  defp handle_error!(text, reason), do: handle_error!(text, {:error, reason, nil})
  defp handle_error!(text, reason, details), do: handle_error!(text, {:error, reason, details})

end
