defmodule P11exCli.KeyUnwrap do
  alias CliMate.CLI

  defp exit, do: Application.fetch_env!(:p11ex_cli, :exit_mod)

  @command name: "p11ex key-unwrap",
    module: __MODULE__,
    options: P11exCli.Common.options() ++ P11exCli.Common.token_options() ++ [
      input_format: [
        short: :f,
        type: :string,
        required: false,
        default: "hex",
        doc: "Input format for wrapped key (binary, hex, base64)"
      ],
      key_label: [
        type: :string,
        required: true,
        doc: "Label for the unwrapped key"
      ],
      key_id: [
        type: :string,
        required: false,
        doc: "Key ID for the unwrapped key (hex-encoded). If not provided, a random ID will be generated."
      ],
      key_type: [
        type: :string,
        required: true,
        doc: "Key type for the unwrapped key (aes, rsa, ec)"
      ],
      key_class: [
        type: :string,
        required: true,
        doc: "Object class for the unwrapped key (seck, prvk, pubk)"
      ],
      encrypt: [
        type: :boolean,
        required: false,
        default: false,
        doc: "Allow to use the key for encryption"
      ],
      decrypt: [
        type: :boolean,
        required: false,
        default: false,
        doc: "Allow to use the key for decryption"
      ],
      sign: [
        type: :boolean,
        required: false,
        default: false,
        doc: "Allow to use the key for signing"
      ],
      verify: [
        type: :boolean,
        required: false,
        default: false,
        doc: "Allow to use the key for verification"
      ],
      wrap: [
        type: :boolean,
        required: false,
        default: false,
        doc: "Allow to use the key for wrapping"
      ],
      unwrap: [
        type: :boolean,
        required: false,
        default: false,
        doc: "Allow to use the key for unwrapping"
      ],
      derive: [
        type: :boolean,
        required: false,
        default: false,
        doc: "Allow to use the key for key derivation"
      ],
      extract: [
        type: :boolean,
        required: false,
        default: false,
        doc: "Mark the key as extractable"
      ],
      token: [
        type: :boolean,
        required: false,
        default: true,
        doc: "Store the key on the token (persistent)"
      ]
    ],
    arguments: [
      mechanism: [
        type: :string,
        required: true,
        doc: "Unwrapping mechanism (e.g., ckm_aes_key_wrap_pad, ckm_rsa_pkcs)"
      ],
      unwrapping_key_ref: [
        type: :string,
        required: true,
        doc: "Reference to unwrapping key (label:name, id:hex, or handle:number)"
      ],
      input_file: [
        type: :string,
        required: true,
        doc: "Path to input file containing wrapped key"
      ]
    ]

  def main(args) do
    res = case CLI.parse(args, @command) do
      {:ok, res} ->
        res
      {:error, reason} ->
        IO.puts("Error parsing arguments: #{inspect(reason)}")
        exit().halt(:invalid_param)
    end

    # Parse input format
    input_format = parse_format!(res.options.input_format)

    # Parse mechanism
    mechanism = parse_mechanism!(res.arguments.mechanism)

    # Parse key type and class
    key_type = parse_key_type!(res.options.key_type)
    key_class = parse_key_class!(res.options.key_class)

    # Load module and login
    P11exCli.Common.load_module(res.options)
    slot = P11exCli.Common.find_slot_by_label!(res.options)
    {:ok, session_pid} = P11exCli.Common.login!(slot, res.options)

    if res.options.verbose do
      IO.puts("Finding unwrapping key: #{res.arguments.unwrapping_key_ref}")
    end

    # Find unwrapping key (try secret key first, then private key)
    unwrapping_key = P11exCli.Common.find_key_by_ref_any_class!(
      session_pid,
      res.arguments.unwrapping_key_ref,
      [:cko_secret_key, :cko_private_key]
    )

    if res.options.verbose do
      IO.puts("Reading wrapped key from: #{res.arguments.input_file}")
    end

    # Read wrapped key bytes
    wrapped_key_bytes = P11exCli.Common.read_wrapped_key(
      res.arguments.input_file,
      input_format)

    if res.options.verbose do
      IO.puts("Read #{byte_size(wrapped_key_bytes)} bytes of wrapped key data")
    end

    # Build attribute template
    attribs = build_attributes(res.options, key_type, key_class)

    if res.options.verbose do
      IO.puts("Unwrapping key with mechanism: #{inspect(mechanism)}")
      IO.puts("Attributes: #{inspect(attribs)}")
    end

    # Unwrap the key
    case P11ex.Session.unwrap_key(
      session_pid,
      mechanism,
      unwrapping_key,
      wrapped_key_bytes,
      attribs
    ) do
      {:ok, unwrapped_key_handle} ->
        IO.puts("Key unwrapped successfully")
        IO.puts("Object handle: #{Integer.to_string(unwrapped_key_handle.handle, 16)}")

        with {:ok, attribs, _failed} <- P11ex.Session.read_object(session_pid, unwrapped_key_handle, key_class) do
          IO.puts("Attributes:")
          attribs
          |> Enum.each(fn {key, value} ->
            IO.puts("  #{key}: #{P11exCli.Common.attrib_value_to_str(value)}")
          end)
        end

        P11ex.Session.logout(session_pid)
        exit().halt(:ok)

      {:error, reason} ->
        IO.puts("Error unwrapping key: #{inspect(reason)}")
        P11ex.Session.logout(session_pid)
        exit().halt(:error)

      {:error, reason, details} ->
        IO.puts("Error unwrapping key: #{inspect(reason)} - #{inspect(details)}")
        P11ex.Session.logout(session_pid)
        exit().halt(:error)
    end
  end

  defp build_attributes(options, key_type, key_class) do
    key_id = make_key_id(options)

    [
      {:cka_class, key_class},
      {:cka_key_type, key_type},
      {:cka_label, options.key_label},
      {:cka_id, key_id},
      {:cka_token, options.token},
      {:cka_encrypt, options.encrypt},
      {:cka_decrypt, options.decrypt},
      {:cka_sign, options.sign},
      {:cka_verify, options.verify},
      {:cka_wrap, options.wrap},
      {:cka_unwrap, options.unwrap},
      {:cka_derive, options.derive},
      {:cka_extractable, options.extract}
    ]
  end

  defp make_key_id(options) do
    with hex_str when is_binary(hex_str) <- Map.get(options, :key_id, nil),
         {:ok, bin} <- Base.decode16(hex_str, case: :mixed) do
      bin
    else
      _ ->
        new_id = :crypto.strong_rand_bytes(16)
        IO.puts("Generated new key ID: #{Base.encode16(new_id, case: :lower)}")
        new_id
    end
  end

  defp parse_mechanism!(mechanism_str) do
    mechanism_atom = String.downcase(mechanism_str) |> String.to_atom()
    {mechanism_atom}
  end

  defp parse_format!(format_str) do
    case String.downcase(format_str) do
      "binary" -> :binary
      "hex" -> :hex
      "base64" -> :base64
      _ ->
        IO.puts("Invalid input format: #{format_str}. Must be binary, hex, or base64")
        exit().halt(:invalid_param)
    end
  end

  defp parse_key_type!(key_type_str) do
    case String.downcase(key_type_str) do
      "aes" -> :ckk_aes
      "rsa" -> :ckk_rsa
      "ec" -> :ckk_ec
      _ ->
        IO.puts("Invalid key type: #{key_type_str}. Must be aes, rsa, or ec")
        exit().halt(:invalid_param)
    end
  end

  defp parse_key_class!(key_class_str) do
    case String.downcase(key_class_str) do
      "seck" -> :cko_secret_key
      "prvk" -> :cko_private_key
      _ ->
        IO.puts("Invalid key class: #{key_class_str}. Must be seck, prvk, or pubk")
        exit().halt(:invalid_param)
    end
  end

  def format_usage do
    IO.puts(CLI.format_usage(@command))
  end
end
