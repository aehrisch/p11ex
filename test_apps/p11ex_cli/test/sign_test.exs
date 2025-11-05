defmodule P11exCli.SignTest do

  use ExUnit.Case, async: false
  import ExUnit.CaptureIO

  alias P11exCli.TestHelper, as: TH

  setup_all do
    TH.setup_all()
  end

  describe "sign" do

    test "no arguments" do
      output = capture_io(:stderr, fn ->
        assert_raise RuntimeError, "halt-error", fn ->
          P11exCli.Sign.main([])
        end
      end)
      assert output =~ "Error parsing arguments:"
    end

    test "show usage" do
      output = capture_io(fn ->
        P11exCli.main(["help", "sign"])
      end)
      assert output =~ ~r/Arguments\n/
      assert output =~ ~r/Options\n/
      assert output =~ ~r/\-\-format/
      assert output =~ ~r/\-\-chunks/
    end

    test "invalid mechanism" do
      output = capture_io(:stderr, fn ->
        assert_raise RuntimeError, "halt-error", fn ->
          P11exCli.Sign.main(["-m", "dummy.so", "-l", "Token_0", "invalid_mechanism", "label:key", "input.dat", "output.dat"])
        end
      end)
      assert output =~ ~r/Invalid mechanism/
    end

    test "invalid format" do
      output = capture_io(:stderr, fn ->
        assert_raise RuntimeError, "halt-error", fn ->
          P11exCli.Sign.main(["-m", "dummy.so", "-l", "Token_0", "-f", "invalid", "rsa_pkcs_plain", "label:key", "input.dat", "output.dat"])
        end
      end)
      assert output =~ ~r/Invalid output format/
    end

    @rsa_algs1 ["rsa_pkcs_plain", "rsa_pkcs_sha1", "rsa_pkcs_sha256", "rsa_pkcs_sha384", "rsa_pkcs_sha512"]
    @rsa_algs2 ["rsa_pkcs_pss_sha256"]

    Enum.each(@rsa_algs1 ++ @rsa_algs2, fn alg ->
      test "sign with #{alg} mechanism", context do
        sig_alg = unquote(alg)
        test_data = "Test data to sign"
        input_file = Path.join(System.tmp_dir!(), "test_input_#{:erlang.unique_integer([:positive])}.dat")
        output_file = Path.join(System.tmp_dir!(), "test_sig_#{:erlang.unique_integer([:positive])}.dat")
        on_exit(fn ->
          File.rm(input_file)
          File.rm(output_file)
        end)

        File.write!(input_file, test_data)

        output = capture_io(fn ->
          P11exCli.Sign.main(context.token_args ++ ["-f", "hex", sig_alg, "label:rsa_4096", input_file, output_file])
        end)

        assert output =~ ~r/Signature written to:/
        assert File.exists?(output_file)
        # Verify the signature is valid hex
        sig_data = File.read!(output_file) |> String.trim()
        assert Base.decode16!(sig_data, case: :mixed)
      end
    end)

    test "sign with ecdsa_sha256 mechanism", context do
      test_data = "Test data to sign with ECDSA"
      input_file = Path.join(System.tmp_dir!(), "test_input_#{:erlang.unique_integer([:positive])}.dat")
      output_file = Path.join(System.tmp_dir!(), "test_sig_#{:erlang.unique_integer([:positive])}.dat")
      on_exit(fn ->
        File.rm(input_file)
        File.rm(output_file)
      end)

      File.write!(input_file, test_data)

      output = capture_io(fn ->
        P11exCli.Sign.main(context.token_args ++ ["-f", "hex", "ecdsa_sha256", "label:ecdsa_p256", input_file, output_file])
      end)

      assert output =~ ~r/Signature written to:/
      assert File.exists?(output_file)
      # Verify the signature is valid hex
      sig_data = File.read!(output_file) |> String.trim()
      assert Base.decode16!(sig_data, case: :mixed)
    end

    test "sign with chunks option", context do
      test_data = :crypto.strong_rand_bytes(16384) # 16KB of random data
      input_file = Path.join(System.tmp_dir!(), "test_input_#{:erlang.unique_integer([:positive])}.dat")
      output_file = Path.join(System.tmp_dir!(), "test_sig_#{:erlang.unique_integer([:positive])}.dat")
      on_exit(fn ->
        File.rm(input_file)
        File.rm(output_file)
      end)

      File.write!(input_file, test_data)

      output = capture_io(fn ->
        P11exCli.Sign.main(context.token_args ++ ["--chunks", "1024", "-f", "bin", "rsa_pkcs_sha256", "label:rsa_4096", input_file, output_file])
      end)

      assert output =~ ~r/Signature written to:/
      assert File.exists?(output_file)
    end

    test "sign with base64 output format", context do
      test_data = "Test data to sign with base64 output"
      input_file = Path.join(System.tmp_dir!(), "test_input_#{:erlang.unique_integer([:positive])}.dat")
      output_file = Path.join(System.tmp_dir!(), "test_sig_#{:erlang.unique_integer([:positive])}.b64")
      on_exit(fn ->
        File.rm(input_file)
        File.rm(output_file)
      end)

      File.write!(input_file, test_data)

      output = capture_io(fn ->
        P11exCli.Sign.main(context.token_args ++ ["-f", "base64", "rsa_pkcs_sha256", "label:rsa_4096", input_file, output_file])
      end)

      assert output =~ ~r/Signature written to:/
      assert File.exists?(output_file)
      sig_data = File.read!(output_file) |> String.trim()
      assert Base.decode64!(sig_data)
    end

  end

end
