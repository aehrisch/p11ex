defmodule P11exCli.KeyGenAes do
  alias CliMate.CLI

  defp exit, do: Application.fetch_env!(:p11ex_cli, :exit_mod)

  @command name: "p11ex key-gen-aes",
    module: __MODULE__,
    options: P11exCli.Common.options() ++ P11exCli.Common.token_options() ++ [
      key_id: [
        type: :string,
        required: false,
        doc: "Key ID for the key. If not provided, a random ID will be generated."
      ],
      encrypt: [
        type: :boolean,
        required: false,
        default: true,
        doc: "Allow to use the key for encryption."
      ],
      decrypt: [
        type: :boolean,
        required: false,
        default: true,
        doc: "Allow to use the key for decryption."
      ],
      sign: [
        type: :boolean,
        required: false,
        default: false,
        doc: "Allow to use the key for signing."
      ],
      verify: [
        type: :boolean,
        required: false,
        default: false,
        doc: "Allow to use the key for verification."
      ],
      wrap: [
        type: :boolean,
        required: false,
        default: false,
        doc: "Allow to use the key for wrapping."
      ],
      unwrap: [
        type: :boolean,
        required: false,
        default: false,
        doc: "Allow to use the key for unwrapping."
      ],
      derive: [
        type: :boolean,
        required: false,
        default: false,
        doc: "Allow to use the key for deriving."
      ],
      extract: [
        type: :boolean,
        required: false,
        default: false,
        doc: "Allow to use the key for extracting."
      ]
    ],
    arguments: [
      key_label: [
        type: :string,
        required: true,
        doc: "Label for the key."
      ],
      key_length: [
        type: :integer,
        required: true,
        doc: "Key length in bits."
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
      P11exCli.Common.load_module(res.options)
      slot = P11exCli.Common.find_slot_by_label!(res.options)
      {:ok, session_pid} = P11exCli.Common.login!(slot, res.options)

      attribs = [
        {:cka_id, make_keyid(res.options)},
        {:cka_encrypt, res.options.encrypt},
        {:cka_decrypt, res.options.decrypt},
        {:cka_sign, res.options.sign},
        {:cka_verify, res.options.verify},
        {:cka_wrap, res.options.wrap},
        {:cka_unwrap, res.options.unwrap},
        {:cka_derive, res.options.derive},
        {:cka_extractable, res.options.extract},
        {:cka_value_len, check_aes_key_length!(res.arguments.key_length)},
        {:cka_token, true}
      ]

      if res.options.verbose do
        IO.puts("Creating key with attributes: #{inspect(attribs)}")
      end

      case P11ex.Session.generate_key(session_pid, {:ckm_aes_key_gen},  attribs) do
        {:ok, key_handle} ->
          IO.puts("Key generated. Object handle: #{Integer.to_string(key_handle.handle, 16)}")
        {:error, reason, details} ->
          IO.puts("Error generating key: #{reason} #{inspect(details)}")
      end

      P11ex.Session.logout(session_pid)
      exit().halt(:ok)
    end

    def make_keyid(options) do
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

    @doc """
    Check if the key length (in bits) is valid for AES. Returns the key length in bytes.
    """
    def check_aes_key_length!(key_length) do
      if key_length not in [128, 192, 256] do
        IO.puts("Invalid key length: #{key_length} must be 128, 192, or 256")
        exit().halt(:error)
      end
      div(key_length, 8)
    end

    def format_usage do
      IO.puts(CLI.format_usage(@command))
    end

end
