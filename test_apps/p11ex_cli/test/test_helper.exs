# Compile test support files
Code.require_file("support/halt_mock.ex", __DIR__)

defmodule P11exCli.TestHelper do

  @sizes [7, 16, 512, 729, 1024, 8192, 65536, 1024*1024, 10*1024*1024, 100*1024*1024]

  def sizes do
    @sizes
  end

  def setup_all do
    Application.put_env(:p11ex_cli, :exit_mod, P11exCli.HaltMock)

    token_pin = System.get_env("TEST_P11EX_PIN") || "1234"
    token_label = System.get_env("TEST_P11EX_TOKEN_LABEL") || "Token_0"
    token_module = System.get_env("TEST_P11EX_MODULE") || raise "TEST_P11EX_MODULE is not set"

    pin_file = write_standard_pin_file(token_pin)

    module_args = [
      "--module", token_module
    ]

    token_args = [
      "--token-label", token_label,
      "--pin-file", pin_file,
      "--module", token_module
    ]

    %{
      pin_file: pin_file,
      token_pin: token_pin,
      token_label: token_label,
      token_module: token_module,
      token_args: token_args,
      module_args: module_args
    }
  end

  def write_standard_pin_file(pin) do
    temp_dir = System.tmp_dir!()
    temp_file = Path.join(temp_dir, "p11ex_cli_pin_#{:erlang.unique_integer([:positive])}.txt")

    File.write!(temp_file, pin)

    System.at_exit(fn _ ->
      if File.exists?(temp_file) do
        File.rm(temp_file)
      end
    end)
    Path.expand(temp_file)
  end

  def write_test_files(sizes \\ @sizes) do
    sizes
    |> Enum.map(fn size ->
      file = Path.join(System.tmp_dir!(), "test_input_#{size}.bin")
      File.write!(file, :crypto.strong_rand_bytes(size))
      {size, file}
    end)
    |> Map.new()
  end

  def cleanup_test_files(sizes \\ @sizes) do
    sizes
    |> Enum.each(fn size ->
      File.rm(Path.join(System.tmp_dir!(), "test_input_#{size}.bin"))
    end)
  end

end


defmodule P11exCli.OpenSSLVerify do
  import ExUnit.Assertions
  import Logger

  def verify(:pss, pubk_file, sig_file, data_file, openssl_digest_alg, salt_len) do
    args =
      ["dgst", openssl_digest_alg, "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:#{salt_len}"] ++
      ["-verify", pubk_file, "-signature", sig_file, data_file]
    really_run(args)
  end

  def verify(:pkcs15, pubk_file, sig_file, data_file, openssl_digest_alg) do
    args =
      ["dgst", openssl_digest_alg, "-verify", pubk_file, "-signature", sig_file, data_file]
    really_run(args)
  end

  def verify(:ecdsa, pubk_file, sig_file, data_file, openssl_digest_alg) do
    args =
      [
        "dgst", openssl_digest_alg,
        "-verify", pubk_file,
        "-signature", sig_file,
        data_file
      ]
    really_run(args)
  end

  defp really_run(args) do
    {output, exit_code} = System.cmd("openssl", args, [stderr_to_stdout: true])
    if exit_code == 0 do
      Logger.debug("success, openssl args #{inspect(args)}")
      :ok
    else
      Logger.warning("openssl signature verification failed (exit code #{exit_code}), args #{inspect(args)}")
      Logger.warning("output: #{output}")
      flunk("openssl signature verification failed (exit code #{exit_code}), args #{inspect(args)}")
      {:error, output}
    end
  end

end



ExUnit.configure(formatters: [JUnitFormatter, ExUnit.CLIFormatter])
ExUnit.start()
