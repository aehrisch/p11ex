defmodule P11exCli.Sign do
  alias CliMate.CLI

  defp exit, do: Application.fetch_env!(:p11ex_cli, :exit_mod)

  @command name: "p11ex sign",
    module: __MODULE__,
    options: P11exCli.Common.options() ++ P11exCli.Common.token_options() ++ [
      chunks: [
        type: :integer,
        required: false,
        doc: "Chunk size in bytes for streaming data. If not specified, all data is read into memory.",
        default: nil
      ],
      format: [
        short: :f,
        type: :string,
        required: false,
        default: "bin",
        doc: "Output format for signature (bin, hex, base64)"
      ]
    ],
    arguments: [
      mechanism: [
        type: :string,
        required: true,
        doc: "Signing mechanism (e.g., rsa_pkcs_plain, rsa_pkcs_sha256, ecdsa_sha256)"
      ],
      key_ref: [
        type: :string,
        required: true,
        doc: "Reference to private key (label:name, id:hex, or handle:number)"
      ],
      input_file: [
        type: :string,
        required: true,
        doc: "Path to input file or '-' for stdin"
      ],
      output_file: [
        type: :string,
        required: true,
        doc: "Path to output file or '-' for stdout"
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
    output_format = parse_format!(res.options.format)

    # Parse mechanism
    mechanism_info = parse_mechanism!(res.arguments.mechanism)

    # Load module and login
    P11exCli.Common.load_module(res.options)
    slot = P11exCli.Common.find_slot_by_label!(res.options)
    {:ok, session_pid} = P11exCli.Common.login!(slot, res.options)

    # Find private key
    private_key = P11exCli.Common.find_key_by_ref!(
      session_pid,
      res.arguments.key_ref,
      :cko_private_key
    )

    # Perform signing
    result = perform_signature(
      session_pid,
      mechanism_info,
      private_key,
      res.arguments.input_file,
      res.options.chunks,
      res.options.verbose
    )

    # Format and write signature
    signature_bytes = case result do
      {:ok, sig} -> sig
      {:error, reason} ->
        IO.puts(:stderr, "Error signing data: #{inspect(reason)}")
        P11ex.Session.logout(session_pid)
        exit().halt(:error)
    end

    formatted_signature = format_signature(signature_bytes, output_format)
    write_output(res.arguments.output_file, formatted_signature)

    if res.options.verbose do
      IO.puts("Signature generated successfully (#{byte_size(signature_bytes)} bytes)")
    end

    P11ex.Session.logout(session_pid)
    exit().halt(:ok)
  end

  # Parse mechanism string into mechanism tuple
  defp parse_mechanism!(mechanism_str) do
    case String.downcase(mechanism_str) do
      "rsa_pkcs_plain" ->
        {{:ckm_rsa_pkcs}, :rsa, false}

      "rsa_pkcs_sha1" ->
        {{:ckm_sha1_rsa_pkcs}, :rsa, false}

      "rsa_pkcs_sha256" ->
        {{:ckm_sha256_rsa_pkcs}, :rsa, false}

      "rsa_pkcs_sha384" ->
        {{:ckm_sha384_rsa_pkcs}, :rsa, false}

      "rsa_pkcs_sha512" ->
        {{:ckm_sha512_rsa_pkcs}, :rsa, false}

      "rsa_pkcs_pss_sha1" ->
        {{:ckm_rsa_pkcs_pss, %{salt_len: 20, hash_alg: :sha, mgf_hash_alg: :sha}}, :rsa, false}

      "rsa_pkcs_pss_sha256" ->
        {{:ckm_rsa_pkcs_pss, %{salt_len: 32, hash_alg: :sha256, mgf_hash_alg: :sha256}}, :rsa, false}

      "ecdsa_plain" ->
        {{:ckm_ecdsa}, :ec, false}

      "ecdsa_sha256" ->
        {{:ckm_ecdsa}, :ec, :sha256}

      "ecdsa_sha384" ->
        {{:ckm_ecdsa}, :ec, :sha384}

      "ecdsa_sha512" ->
        {{:ckm_ecdsa}, :ec, :sha512}

      _ ->
        IO.puts(:stderr, "Invalid mechanism: #{mechanism_str}")
        exit().halt(:invalid_param)
    end
  end

  # Parse output format string
  defp parse_format!(format_str) do
    case String.downcase(format_str) do
      "bin" -> :bin
      "hex" -> :hex
      "base64" -> :base64
      _ ->
        IO.puts(:stderr, "Invalid output format: #{format_str}. Must be bin, hex, or base64")
        exit().halt(:invalid_param)
    end
  end

  # Main signing logic
  defp perform_signature(session_pid, {mechanism, _key_type, hash_alg}, key, input_file, chunks, verbose) do
    # Check if we need to pre-hash (for ECDSA mechanisms)
    needs_pre_hash = hash_alg != false

    if needs_pre_hash do
      if chunks != nil do
        IO.puts(:stderr, "Warning: --chunks option ignored for hashed ECDSA signatures")
      end
      perform_hash_and_sign(session_pid, mechanism, key, input_file, hash_alg, verbose)
    else
      # Perform regular signing
      perform_regular_sign(session_pid, mechanism, key, input_file, chunks, verbose)
    end
  end

  # Perform signing for mechanisms that require pre-hashing (ECDSA with hash)
  defp perform_hash_and_sign(session_pid, mechanism, key, input_file, hash_alg, verbose) do
    if verbose do
      IO.puts("Reading input data for hashing...")
    end

    data = read_input_data(input_file)

    if verbose do
      IO.puts("Computing #{hash_alg} hash over #{byte_size(data)} bytes")
    end

    digest = :crypto.hash(hash_alg, data)

    if verbose do
      IO.puts("Initializing signing operation with mechanism: #{inspect(mechanism)}")
    end

    case P11ex.Session.sign_init(session_pid, mechanism, key) do
      :ok ->
        case P11ex.Session.sign(session_pid, digest) do
          {:ok, signature} -> {:ok, signature}
          {:error, reason} -> {:error, reason}
          {:error, reason, details} -> {:error, reason, details}
        end

      {:error, reason} ->
        {:error, reason}

      {:error, reason, details} ->
        {:error, reason, details}
    end
  end

  # Perform regular signing (without pre-hashing)
  defp perform_regular_sign(session_pid, mechanism, key, input_file, chunks, verbose) do
    if verbose do
      IO.puts("Initializing signing operation with mechanism: #{inspect(mechanism)}")
    end

    case P11ex.Session.sign_init(session_pid, mechanism, key) do
      :ok ->
        if chunks != nil do
          perform_chunked_sign(session_pid, input_file, chunks, verbose)
        else
          perform_single_sign(session_pid, input_file, verbose)
        end

      {:error, reason} ->
        {:error, reason}

      {:error, reason, details} ->
        {:error, reason, details}
    end
  end

  # Perform signing in chunks
  defp perform_chunked_sign(session_pid, input_file, chunk_size, verbose) do
    if verbose do
      IO.puts("Signing data in chunks of #{chunk_size} bytes")
    end

    # Read and sign in chunks
    case read_in_chunks(input_file, chunk_size, fn data ->
      case P11ex.Session.sign_update(session_pid, data) do
        :ok -> :ok
        err -> err
      end
    end) do
      :ok ->
        # Finalize signing
        P11ex.Session.sign_final(session_pid)

      {:error, reason} ->
        {:error, reason}

      {:error, reason, details} ->
        {:error, reason, details}
    end
  end

  # Perform signing in a single operation
  defp perform_single_sign(session_pid, input_file, verbose) do
    if verbose do
      IO.puts("Signing data in a single operation")
    end

    data = read_input_data(input_file)

    if verbose do
      IO.puts("Signing #{byte_size(data)} bytes of data")
    end

    case P11ex.Session.sign(session_pid, data) do
      {:ok, signature} -> {:ok, signature}
      {:error, reason} -> {:error, reason}
      {:error, reason, details} -> {:error, reason, details}
    end
  end

  # Read input data (file or stdin)
  defp read_input_data(file_path) do
    if file_path == "-" do
      # Read from stdin
      read_from_stdin()
    else
      case File.read(file_path) do
        {:ok, data} -> data
        {:error, reason} ->
          IO.puts(:stderr, "Error reading input file: #{inspect(reason)}")
          exit().halt(:error)
      end
    end
  end

  # Read from stdin
  defp read_from_stdin do
    IO.binread(:stdio, :all)
  end

  # Read data in chunks and call callback for each chunk
  defp read_in_chunks(file_path, chunk_size, callback) do
    if file_path == "-" do
      # Read from stdin in chunks
      stdin_chunk_size = Application.get_env(:p11ex_cli, [:sign, :stdin_chunk_size], 8192)
      read_stdin_in_chunks(stdin_chunk_size, callback)
    else
      # Read from file in chunks
      case File.open(file_path, [:read, :binary]) do
        {:ok, fd} ->
          result = read_file_in_chunks(fd, chunk_size, callback)
          File.close(fd)
          result

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  # Read stdin in chunks
  defp read_stdin_in_chunks(chunk_size, callback) do
    case IO.binread(:stdio, chunk_size) do
      :eof ->
        :ok

      data ->
        case callback.(data) do
          :ok ->
            # Continue reading
            read_stdin_in_chunks(chunk_size, callback)
          err -> err
        end
    end
  end

  # Read file in chunks
  defp read_file_in_chunks(fd, chunk_size, callback) do
    case IO.binread(fd, chunk_size) do
      :eof ->
        :ok

      data ->
        case callback.(data) do
          :ok ->
            # Continue reading
            read_file_in_chunks(fd, chunk_size, callback)
          err -> err
        end
    end
  end

  # Format signature based on output format
  defp format_signature(signature, :bin), do: signature
  defp format_signature(signature, :hex), do: Base.encode16(signature, case: :lower)
  defp format_signature(signature, :base64), do: Base.encode64(signature)

  # Write output (file or stdout)
  defp write_output(file_path, data) do
    if file_path == "-" do
      IO.binwrite(:stdout, data)
    else
      case File.write(file_path, data) do
        :ok ->
          IO.puts("Signature written to: #{file_path}")
        {:error, reason} ->
          IO.puts(:stderr, "Error writing output file: #{inspect(reason)}")
          exit().halt(:error)
      end
    end
  end

  def format_usage do
    IO.puts(CLI.format_usage(@command))
  end
end
