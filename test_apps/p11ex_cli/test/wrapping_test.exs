defmodule P11exCli.KeyWrapTest do

  use ExUnit.Case, async: false
  import ExUnit.CaptureIO

  alias P11exCli.TestHelper, as: TH

  setup_all do
    TH.setup_all()
  end

  describe "key-wrap" do

    test "no arguments" do
      output = capture_io(fn ->
        assert_raise RuntimeError, "halt-error", fn ->
          P11exCli.KeyWrap.main([])
        end
      end)
      assert output =~ "Error parsing arguments:"
    end

    test "show usage", context do
      output = capture_io(fn ->
        P11exCli.main(["help", "key-wrap"])
      end)
      assert output =~ ~r/Arguments\n/
      assert output =~ ~r/Options\n/
      assert output =~ ~r/\-\-output\-format/
    end

  end

  describe "wrap/unwrap with AES key" do

    test "happy path with (hex format)", context do
      temp_file = Path.join(System.tmp_dir!(), "test_#{:erlang.unique_integer([:positive])}.hex")
      on_exit(fn -> File.rm(temp_file) end)

      output = capture_io(fn ->
        P11exCli.KeyWrap.main(context.token_args ++ ["ckm_aes_key_wrap_pad", "label:wrapping_aes", "label:extractable_aes", temp_file, "-f", "hex", "-v"])
      end)
      assert output =~ ~r/Wrapped key written to:/
      assert output =~ ~r/#{temp_file}/
      assert File.exists?(temp_file)
      assert File.read!(temp_file) |> Base.decode16!(case: :lower)

      new_label = "unwrapped_aes_#{:erlang.unique_integer([:positive])}"
      output2 = capture_io(fn ->
        unwrap_args = ["--key-label", new_label, "--key-type", "aes", "--key-class", "seck", "--encrypt", "--decrypt", "-f", "hex", "-v"]
        P11exCli.KeyUnwrap.main(context.token_args ++ unwrap_args ++ ["ckm_aes_key_wrap_pad", "label:wrapping_aes", temp_file])
      end)

      assert output2 =~ ~r/Key unwrapped successfully/
      assert output2 =~ ~r/Attributes:/
      assert output2 =~ ~r/Object handle:/
      assert output2 =~ ~r/#{new_label}/
      assert File.exists?(temp_file)
      assert File.read!(temp_file) |> Base.decode16!(case: :lower)
    end

    test "happy path with binary output", context do
      temp_file = Path.join(System.tmp_dir!(), "test_#{:erlang.unique_integer([:positive])}.bin")
      on_exit(fn -> File.rm(temp_file) end)

      output = capture_io(fn ->
        P11exCli.KeyWrap.main(context.token_args ++ ["ckm_aes_key_wrap_pad", "label:wrapping_aes", "label:extractable_aes", temp_file, "-f", "binary", "-v"])
      end)
      assert output =~ ~r/Wrapped key written to:/
      assert output =~ ~r/#{temp_file}/
      assert File.exists?(temp_file)
    end

    test "happy path with base64 output", context do
      temp_file = Path.join(System.tmp_dir!(), "test_#{:erlang.unique_integer([:positive])}.b64")
      on_exit(fn -> File.rm(temp_file) end)

      output = capture_io(fn ->
        P11exCli.KeyWrap.main(context.token_args ++ ["ckm_aes_key_wrap_pad", "label:wrapping_aes", "label:extractable_aes", temp_file, "-f", "base64", "-v"])
      end)
      assert output =~ ~r/Wrapped key written to:/
      assert output =~ ~r/#{temp_file}/
      assert File.exists?(temp_file)
      assert File.read!(temp_file) |> Base.decode64!()
    end
  end

  describe "wrap with RSA key" do

    test "happy path with hex output", context do
      temp_file = Path.join(System.tmp_dir!(), "test_#{:erlang.unique_integer([:positive])}.hex")
      on_exit(fn -> File.rm(temp_file) end)

      output = capture_io(fn ->
        P11exCli.KeyWrap.main(context.token_args ++ ["ckm_rsa_pkcs", "label:wrapping_rsa", "label:extractable_aes", temp_file, "-f", "hex", "-v"])
      end)
      assert output =~ ~r/Wrapped key written to:/
      assert output =~ ~r/#{temp_file}/
      assert File.exists?(temp_file)
      assert File.read!(temp_file) |> Base.decode16!(case: :lower)
    end

    test "happy path with binary output", context do
      temp_file = Path.join(System.tmp_dir!(), "test_#{:erlang.unique_integer([:positive])}.bin")
      on_exit(fn -> File.rm(temp_file) end)

      output = capture_io(fn ->
        P11exCli.KeyWrap.main(context.token_args ++ ["ckm_aes_key_wrap_pad", "label:wrapping_aes", "label:extractable_aes", temp_file, "-f", "binary", "-v"])
      end)
      assert output =~ ~r/Wrapped key written to:/
      assert output =~ ~r/#{temp_file}/
      assert File.exists?(temp_file)
    end

    test "happy path with base64 output", context do
      temp_file = Path.join(System.tmp_dir!(), "test_#{:erlang.unique_integer([:positive])}.b64")
      on_exit(fn -> File.rm(temp_file) end)

      output = capture_io(fn ->
        P11exCli.KeyWrap.main(context.token_args ++ ["ckm_aes_key_wrap_pad", "label:wrapping_aes", "label:extractable_aes", temp_file, "-f", "base64", "-v"])
      end)
      assert output =~ ~r/Wrapped key written to:/
      assert output =~ ~r/#{temp_file}/
      assert File.exists?(temp_file)
      assert File.read!(temp_file) |> Base.decode64!()
    end
  end


end
