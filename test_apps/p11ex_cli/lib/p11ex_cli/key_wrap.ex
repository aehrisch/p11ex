defmodule P11exCli.KeyWrap do
  alias CliMate.CLI

  defp exit, do: Application.fetch_env!(:p11ex_cli, :exit_mod)

  @command name: "p11ex key-wrap",
    module: __MODULE__,
    options: P11exCli.Common.options() ++ P11exCli.Common.token_options() ++ [
      output_format: [
        short: :f,
        type: :string,
        required: false,
        default: "hex",
        doc: "Output format for wrapped key (binary, hex, base64)"
      ]
    ],
    arguments: [
      mechanism: [
        type: :string,
        required: true,
        doc: "Wrapping mechanism (e.g., ckm_aes_key_wrap_pad, ckm_rsa_pkcs)"
      ],
      wrapping_key_ref: [
        type: :string,
        required: true,
        doc: "Reference to wrapping key (label:name, id:hex, or handle:number)"
      ],
      key_ref: [
        type: :string,
        required: true,
        doc: "Reference to key to wrap (label:name, id:hex, or handle:number)"
      ],
      output_file: [
        type: :string,
        required: true,
        doc: "Path to output file for wrapped key"
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

    # Parse output format
    output_format = parse_format!(res.options.output_format)

    # Parse mechanism
    mechanism = parse_mechanism!(res.arguments.mechanism)

    # Load module and login
    P11exCli.Common.load_module(res.options)
    slot = P11exCli.Common.find_slot_by_label!(res.options)
    {:ok, session_pid} = P11exCli.Common.login!(slot, res.options)

    if res.options.verbose do
      IO.puts("Finding wrapping key: #{res.arguments.wrapping_key_ref}")
    end

    # Find wrapping key (try secret key first, then public key)
    wrapping_key = P11exCli.Common.find_key_by_ref_any_class!(
      session_pid,
      res.arguments.wrapping_key_ref,
      [:cko_secret_key, :cko_public_key]
    )

    if res.options.verbose do
      IO.puts("Finding key to wrap: #{res.arguments.key_ref}")
    end

    # Find key to wrap (can be any key type)
    key_to_wrap = P11exCli.Common.find_key_by_ref_any_class!(
      session_pid,
      res.arguments.key_ref,
      [:cko_secret_key, :cko_private_key, :cko_public_key]
    )

    if res.options.verbose do
      IO.puts("Wrapping key with mechanism: #{inspect(mechanism)}")
    end

    # Wrap the key
    case P11ex.Session.wrap_key(session_pid, mechanism, wrapping_key, key_to_wrap) do
      {:ok, wrapped_key_bytes} ->
        if res.options.verbose do
          IO.puts("Key wrapped successfully (#{byte_size(wrapped_key_bytes)} bytes)")
        end

        # Write wrapped key to file
        P11exCli.Common.write_wrapped_key(
          res.arguments.output_file,
          wrapped_key_bytes,
          output_format
        )

        IO.puts("Wrapped key written to: #{res.arguments.output_file}")
        P11ex.Session.logout(session_pid)
        exit().halt(:ok)

      {:error, reason} ->
        IO.puts("Error wrapping key: #{inspect(reason)}")
        P11ex.Session.logout(session_pid)
        exit().halt(:error)

      {:error, reason, details} ->
        IO.puts("Error wrapping key: #{inspect(reason)} - #{inspect(details)}")
        P11ex.Session.logout(session_pid)
        exit().halt(:error)
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
        IO.puts("Invalid output format: #{format_str}. Must be binary, hex, or base64")
        exit().halt(:invalid_param)
    end
  end

  def format_usage do
    IO.puts(CLI.format_usage(@command))
  end
end
