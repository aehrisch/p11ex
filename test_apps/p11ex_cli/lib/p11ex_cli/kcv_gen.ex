defmodule P11exCli.KcvGen do
  alias CliMate.CLI

  defp exit, do: Application.fetch_env!(:p11ex_cli, :exit_mod)

  @command name: "p11ex kcv-gen",
    module: __MODULE__,
    options: P11exCli.Common.options() ++ P11exCli.Common.token_options() ++ P11exCli.Common.output_options(),
    arguments: [
      key_ref: [
        type: :string,
        required: true,
        doc: "Reference to key (label:name, id:hex, or handle:number)",
        repeat: true
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
    output_format = P11exCli.Common.check_output_format!(res.options)
    P11exCli.Common.load_module(res.options)
    slot = P11exCli.Common.find_slot_by_label!(res.options)
    {:ok, session_pid} = P11exCli.Common.login!(slot, res.options)

    results = Enum.map(res.arguments.key_ref, fn key_ref ->
      %{ref: key_ref, result: compute_kcv(session_pid, key_ref)}
    end)

    output_results(results, output_format)

    P11ex.Session.logout(session_pid)
    exit().halt(:ok)
  end

  defp compute_kcv(session_pid, ref_str) do
    with {:ok, key} <- P11exCli.Common.find_key_by_ref(session_pid, ref_str, :cko_secret_key),
         {:ok, block} <- P11ex.Session.encrypt(session_pid, {:ckm_aes_ecb}, key, <<0::size(128)>>),
         kcv <- "0x" <> (binary_part(block, 0, 3) |> Base.encode16(case: :lower)) do
      %{handle: key.handle, status: :ok, kcv: kcv}
    else
      {:error, reason, _details} ->
        %{handle: nil, status: :error, reason: inspect(reason)}
    end
  end

  defp output_results(results, output_format) do
    case output_format do
      :json ->
        IO.puts(Jason.encode!(results, pretty: true))
      :text ->
        results |> Enum.each(fn %{ref: ref, result: result} ->
          IO.puts("Key reference: #{ref}")
          case result.status do
            :ok ->
              IO.puts("  Handle: #{result.handle}")
              IO.puts("  KCV: #{result.kcv}")
            :error ->
              IO.puts("  Error: #{result.reason}")
          end
      end)
    end
  end

  def format_usage do
    IO.puts(CLI.format_usage(@command))
  end

end
