defmodule P11exCli.SignOptionsTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureIO
  import ExUnit.CaptureLog

  require Logger

  alias P11exCli.TestHelper, as: TH
  alias P11exCli.OpenSSLVerify, as: OpenSSL


  setup_all do
    context1 = TH.setup_all()
    rsa_pubk_file = Path.join(System.tmp_dir!(), "rsa_4096.pem")
    rsa_pem = capture_io(fn ->
      P11exCli.ExportPubk.main(context1.token_args ++ ["label:rsa_4096"])
    end)
    File.write!(rsa_pubk_file, rsa_pem)
    Logger.debug("wrote rsa public key to #{rsa_pubk_file}")

    on_exit(fn ->
      File.rm(rsa_pubk_file)
    end)
    Map.merge(context1, %{rsa_pubk_file: rsa_pubk_file})
  end

  describe "unknown signature format" do
    test "sign" do
      output = capture_io(:stderr, fn ->
        assert_raise RuntimeError, "halt-error", fn ->
          P11exCli.Sign.main(["-f", "invalid", "rsa_pkcs", "sha256", "label:rsa_4096", "input.dat", "output.dat"])
        end
      end)
      assert output =~ ~r/Invalid output format/
    end
  end

  describe "signature output format conversion" do

    test "sign with different output formats", context do
      data = :crypto.strong_rand_bytes(8192)
      data_file = Path.join(System.tmp_dir!(), "data.bin")
      File.write!(data_file, data)

      digest = :crypto.hash(:sha256, data)
      digest_file = Path.join(System.tmp_dir!(), "digest.bin")
      File.write!(digest_file, digest)

      sig_file_bin = Path.join(System.tmp_dir!(), "sig.bin")
      sig_file_hex = Path.join(System.tmp_dir!(), "sig.hex")
      sig_file_base64 = Path.join(System.tmp_dir!(), "sig.base64")
      sig_file_hex_decoded = Path.join(System.tmp_dir!(), "sig.hex.decoded")
      sig_file_base64_decoded = Path.join(System.tmp_dir!(), "sig.base64.decoded")

      on_exit(fn ->
        File.rm(data_file)
        File.rm(digest_file)
        File.rm(sig_file_bin)
        File.rm(sig_file_hex)
        File.rm(sig_file_base64)
        File.rm(sig_file_hex_decoded)
        File.rm(sig_file_base64_decoded)
      end)

      output = capture_io(fn ->
        P11exCli.Sign.main(context.token_args ++ ["-f", "bin", "rsa_pkcs", "sha256", "label:rsa_4096", digest_file, sig_file_bin])
      end)
      assert output =~ ~r/Signature written to: #{sig_file_bin}/
      assert File.exists?(sig_file_bin)

      output = capture_io(fn ->
        P11exCli.Sign.main(context.token_args ++ ["-f", "hex", "rsa_pkcs", "sha256", "label:rsa_4096", digest_file, sig_file_hex])
      end)
      assert output =~ ~r/Signature written to: #{sig_file_hex}/
      assert File.exists?(sig_file_hex)

      output = capture_io(fn ->
        P11exCli.Sign.main(context.token_args ++ ["-f", "base64", "rsa_pkcs", "sha256", "label:rsa_4096", digest_file, sig_file_base64])
      end)
      assert output =~ ~r/Signature written to: #{sig_file_base64}/
      assert File.exists?(sig_file_base64)

      pubk_file = context.rsa_pubk_file

      OpenSSL.verify(:pkcs15, pubk_file, sig_file_bin, digest_file, "-sha256")

      decoded_hex = File.read!(sig_file_hex) |> Base.decode16!(case: :lower)
      File.write!(sig_file_hex_decoded, decoded_hex)
      OpenSSL.verify(:pkcs15, pubk_file, sig_file_hex_decoded, digest_file, "-sha256")

      decoded_base64 = File.read!(sig_file_base64) |> Base.decode64!()
      File.write!(sig_file_base64_decoded, decoded_base64)
      OpenSSL.verify(:pkcs15, pubk_file, sig_file_base64_decoded, digest_file, "-sha256")
    end

  end


end
