# Compile test support files
Code.require_file("support/halt_mock.ex", __DIR__)

defmodule P11exCli.TestHelper do

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

end

ExUnit.start()
