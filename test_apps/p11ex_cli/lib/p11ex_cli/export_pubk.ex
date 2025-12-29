defmodule P11exCli.ExportPubk do
  alias CliMate.CLI
  require Record

  defp exit, do: Application.fetch_env!(:p11ex_cli, :exit_mod)

  @command name: "p11ex export-pubk",
    module: __MODULE__,
    options: P11exCli.Common.options() ++ P11exCli.Common.token_options(),
    arguments: [
      key_ref: [
        type: :string,
        required: true,
        doc: "Reference to public key (label:name, id:hex, or handle:number)"
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

    # Load module and login
    P11exCli.Common.load_module(res.options)
    slot = P11exCli.Common.find_slot_by_label!(res.options)
    {:ok, session_pid} = P11exCli.Common.login!(slot, res.options)

    if res.options.verbose do
      IO.puts("Finding public key: #{res.arguments.key_ref}")
    end

    # Find public key
    public_key = P11exCli.Common.find_key_by_ref!(
      session_pid,
      res.arguments.key_ref,
      :cko_public_key)

    if res.options.verbose do
      IO.puts("Reading public key attributes")
    end

    # Read key attributes to determine key type
    common_attribs = P11exCli.Common.carefully_read_object(
      session_pid,
      public_key,
      P11ex.Lib.ObjectAttributes.public_key())

    key_type = common_attribs[:cka_key_type]

    # Read full attributes based on key type
    attribs = case key_type do
      :ckk_rsa ->
        attribs = P11exCli.Common.carefully_read_object(
          session_pid,
          public_key,
          [:cka_modulus, :cka_public_exponent])
        Map.merge(common_attribs, attribs)

      key_type when key_type in [:ckk_ec, :ckk_ecdsa] ->
        attribs = P11exCli.Common.carefully_read_object(
          session_pid,
          public_key,
          [:cka_ec_params, :cka_ec_point])
        Map.merge(common_attribs, attribs)

      _ ->
        IO.puts(:stderr, "Unsupported key type: #{inspect(key_type)}")
        P11ex.Session.logout(session_pid)
        exit().halt(:invalid_param)
    end

    if res.options.verbose do
      IO.puts("Exporting #{inspect(key_type)} public key in #{res.options.format} format")
    end

    # Convert to SubjectPublicKeyInfo and encode
    encoded_key = case key_type do
      :ckk_rsa ->
        export_rsa_key(attribs)

      key_type when key_type in [:ckk_ec, :ckk_ecdsa] ->
        export_ec_key(attribs)
    end

    IO.binwrite(encoded_key)

    P11ex.Session.logout(session_pid)
    exit().halt(:ok)
  end

  # Export RSA public key
  defp export_rsa_key(attribs) do
    modulus = attribs[:cka_modulus]
    exponent = attribs[:cka_public_exponent]

    if modulus == :inaccessible or exponent == :inaccessible do
      IO.puts(:stderr, "Error: Key attributes are inaccessible")
      exit().halt(:error)
    end

    # Create a SubjectPublicKeyInfo record with the RSAPublicKey structure.
    # This format is compatible with OpenSSL.
    rsa_public_key = {:"RSAPublicKey", modulus, exponent}
    subject_public_key_info =
      {:"SubjectPublicKeyInfo",
        {:AlgorithmIdentifier, {1, 2, 840, 113549, 1, 1, 1}, :NULL},
        :public_key.der_encode(:"RSAPublicKey", rsa_public_key)}

    der = :public_key.der_encode(:"SubjectPublicKeyInfo", subject_public_key_info)

    encode_output(der, :pem)
  end

  # Export EC public key
  defp export_ec_key(attribs) do
    ec_params = attribs[:cka_ec_params]
    ec_point = attribs[:cka_ec_point]

    if ec_params == :inaccessible or ec_point == :inaccessible do
      IO.puts(:stderr, "Error: Key attributes are inaccessible")
      exit().halt(:error)
    end

    with {:ok, point_bytes} when is_binary(point_bytes) <- :EC.decode(:ECPoint, ec_point),
         {:ok, {:namedCurve, curve_oid}} <- :EC.decode(:ECParameters, ec_params) do

      subject_public_key_info =
        {:"SubjectPublicKeyInfo",
          {:AlgorithmIdentifier, {1, 2, 840, 10045, 2, 1}, {:namedCurve, curve_oid}},
          point_bytes}

      der = :public_key.der_encode(:"SubjectPublicKeyInfo", subject_public_key_info)
      encode_output(der, :pem)
    else
      {:error, reason} ->
        IO.puts(:stderr, "Error decoding EC parameters or point: #{inspect(reason)}")
        exit().halt(:error)
    end
  end

  defp encode_output(der, :pem) do
    # Create PEM entry tuple with SubjectPublicKeyInfo tag and DER data
    entry = {:SubjectPublicKeyInfo, der, :not_encrypted}
    pem_bin = :public_key.pem_encode([entry])
    [pem_bin, "\n"]
  end

  def format_usage do
    IO.puts(CLI.format_usage(@command))
  end
end
