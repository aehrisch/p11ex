defmodule P11exCli.ObjectList do
  alias CliMate.CLI

  defp exit, do: Application.fetch_env!(:p11ex_cli, :exit_mod)

  @command name: "p11ex list-objects",
    module: __MODULE__,
    options: P11exCli.Common.options() ++  P11exCli.Common.token_options() ++ P11exCli.Common.output_options(),
    arguments: [
      object_type: [
        type: :string,
        required: true,
        doc: "Object type to list (seck, prvk, pubk)"
      ],

    ]
  def main(args) do
    res = case CLI.parse(args, @command) do
      {:ok, res} ->
        res
      {:error, reason} ->
        IO.puts("Error parsing arguments: #{inspect(reason)}")
        exit().halt(:invalid_param)
    end

    obj_class = check_object_type!(res.arguments.object_type)
    output_format = P11exCli.Common.check_output_format!(res.options)

    P11exCli.Common.load_module(res.options)
    slot = P11exCli.Common.find_slot_by_label!(res.options)
    {:ok, session_pid} = P11exCli.Common.login!(slot, res.options)

    find_objects(session_pid, obj_class, output_format)
  end

  def format_usage do
    IO.puts(CLI.format_usage(@command))
  end

  defp find_objects(session_pid, obj_class, output_format) do

    attribs = [{:cka_class, obj_class}]

    case P11ex.Session.find_objects(session_pid, attribs, 10) do
      {:ok, objects} ->
        objects_and_attribs =
          objects
            |> Enum.map(fn object -> {object, P11ex.Session.read_object(session_pid, object, obj_class)} end)
            |> Enum.filter(fn {_, {:ok, _, _}} -> true end)
            |> Enum.map(fn {object, {:ok, attribs, _rest}} -> {object, attribs} end)
        output_objects(objects_and_attribs, output_format)
        P11ex.Session.logout(session_pid)
        exit().halt(:ok)
      {:error, reason, details} ->
        IO.puts("Error listing objects: #{inspect(reason)} #{inspect(details)}")
        exit().halt(:error)
    end
  end

  defp check_object_type!(object_type) do
    case object_type do
      "seck" -> :cko_secret_key
      "prvk" -> :cko_private_key
      "pubk" -> :cko_public_key
      _ ->
        IO.puts("Invalid object type: #{object_type}")
        exit().halt(:invalid_param)
    end
  end

  defp output_objects(objects_and_attribs, output_format) do

    case output_format do

      :json ->
        objects_and_attribs
        |> Enum.map(fn {object, attribs} ->
            attribs = attribs
              |> Enum.map(fn {key, value} ->
                  %{attrib: key,
                    value: P11exCli.Common.attrib_value_to_str(value)}
                end)
            %{handle: object.handle, attribs: attribs}
          end)
        |> Jason.encode!()
        |> IO.puts()

      :text ->
        objects_and_attribs
        |> Enum.each(fn {object, attribs} ->
            IO.puts("Object handle: #{object.handle}")
            attribs
            |> Enum.each(fn {key, value} ->
              IO.puts("  #{key}: #{P11exCli.Common.attrib_value_to_str(value)}")
            end)
          end)
    end
  end

end
