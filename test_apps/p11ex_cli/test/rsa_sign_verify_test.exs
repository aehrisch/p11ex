defmodule P11exCli.RsaSignVerifyTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureIO

  require Logger

  alias P11exCli.TestHelper, as: TH

  setup_all context do
    context1 = TH.setup_all()

    # Export RSA public key to file so that OpenSSL can read it
    rsa_pubk_file = Path.join(System.tmp_dir!(), "rsa_4096.pem")
    rsa_pem = capture_io(fn ->
      P11exCli.ExportPubk.main(context1.token_args ++ ["label:rsa_4096"])
    end)
    File.write!(rsa_pubk_file, rsa_pem)
    Logger.debug("wrote rsa public key to #{rsa_pubk_file}")

    test_files = TH.write_test_files()

    # Clean up the public key files and test files after tests are done
    on_exit(fn ->
      File.rm(rsa_pubk_file)
      TH.cleanup_test_files()
    end)

    Map.merge(context, context1)
    |> Map.merge(%{rsa_pubk_file: rsa_pubk_file, test_files: test_files})
  end

  @doc """
  Use OpenSSL to verify a PKCS#1 v1.5 signature.
  """
  def openssl_verify(:pkcs15, pubk_file, sig_file, data_file, openssl_digest_alg) do
    args = ["dgst", openssl_digest_alg, "-verify", pubk_file, "-signature", sig_file, data_file]
    {output, exit_code} = System.cmd("openssl", args)
    if exit_code == 0 do
      Logger.debug("success, openssl args #{inspect(args)}")
      :ok
    else
      flunk("openssl signature verification failed (exit code #{exit_code}), args #{inspect(args)}")
      {:error, output}
    end
  end

  @pkcs15_algs [
    {"rsa_pkcs_sha1", "-sha1"},
    {"rsa_pkcs_sha256", "-sha256"},
    {"rsa_pkcs_sha384", "-sha384"},
    {"rsa_pkcs_sha512", "-sha512"}
  ]

  describe "RSA PKCS#1 v1.5 sign and verify (no chunks)" do
    Enum.each(TH.sizes(), fn size ->
      Enum.each(@pkcs15_algs, fn {p11_alg, openssl_digest_alg} ->
        test "#{p11_alg} size #{size} bytes", context do

          data_file = Enum.find_value(context.test_files, fn {s, f} -> if s == unquote(size), do: f end)
          sig_file = Path.join(System.tmp_dir!(), "sig_#{unquote(p11_alg)}_" <> to_string(unquote(size)) <> ".bin")
          P11exCli.Sign.main(context.token_args ++ [unquote(p11_alg), "label:rsa_4096", data_file, sig_file])

          on_exit(fn ->
            File.rm(sig_file)
          end)

          openssl_verify(:pkcs15, context.rsa_pubk_file, sig_file, data_file, unquote(openssl_digest_alg))
        end
      end)
    end)
  end

  @chunks [1024, 8192, 65536, 1024*1024]

  describe "RSA PKCS#1 v1.5 sign and verify (in chunks)" do
    Enum.each(@chunks, fn chunk ->
      Enum.each(TH.sizes(), fn size ->
        Enum.each(@pkcs15_algs, fn {p11_alg, openssl_digest_alg} ->
          test "#{p11_alg} size #{size} bytes, chunk #{chunk}", context do

            data_file = Enum.find_value(context.test_files, fn {s, f} -> if s == unquote(size), do: f end)
            sig_file = Path.join(System.tmp_dir!(), "sig_#{unquote(p11_alg)}_" <> to_string(unquote(size)) <> "_chunk_#{unquote(chunk)}.bin")
            P11exCli.Sign.main(context.token_args ++ ["--chunks", to_string(unquote(chunk)), unquote(p11_alg), "label:rsa_4096", data_file, sig_file])

            on_exit(fn ->
              File.rm(sig_file)
            end)

            openssl_verify(:pkcs15, context.rsa_pubk_file, sig_file, data_file, unquote(openssl_digest_alg))
          end
        end)
      end)

    end)
  end

end
