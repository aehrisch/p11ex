defmodule P11exCli.SignHashRSAVerifyTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureIO

  require Logger

  alias P11exCli.TestHelper, as: TH
  alias P11exCli.OpenSSLVerify, as: OpenSSL

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

  @rsa_pss_algs1 [
    {"rsa_pkcs_pss", "-sha1", 20, :sha},
    {"rsa_pkcs_pss", "-sha224", 28, :sha224},
    {"rsa_pkcs_pss", "-sha256", 32, :sha256},
    {"rsa_pkcs_pss", "-sha384", 48, :sha384},
    {"rsa_pkcs_pss", "-sha512", 64, :sha512}
  ]

  describe "sign unhashed data with RSA PSS mechanisms and verify" do
    Enum.each(@rsa_pss_algs1, fn {p11_alg, openssl_digest_alg, salt_len, hash_alg} ->
      test "#{p11_alg} hash #{hash_alg}", context do

        data = :crypto.strong_rand_bytes(8192)
        suffix = "#{unquote(p11_alg)}_#{unquote(hash_alg)}"

        data_file = Path.join(System.tmp_dir!(), "data_#{suffix}.bin")
        File.write!(data_file, data)

        sig_file = Path.join(System.tmp_dir!(), "sig_#{suffix}.bin")

        on_exit(fn ->
          File.rm(data_file)
          File.rm(sig_file)
        end)

        output = capture_io(fn ->
          P11exCli.Sign.main(context.token_args ++ [unquote(p11_alg), Atom.to_string(unquote(hash_alg)), "label:rsa_4096", data_file, sig_file])
        end)

        assert output =~ ~r/Signature written to: #{sig_file}/
        assert File.exists?(sig_file)

        OpenSSL.verify(:pss, context.rsa_pubk_file, sig_file, data_file, unquote(openssl_digest_alg), unquote(salt_len))
      end
    end)
  end

  @rsa_pss_algs2 [
    {"rsa_pkcs_pss_sha", "-sha1", 20, :sha},
    {"rsa_pkcs_pss_sha224", "-sha224", 28, :sha224},
    {"rsa_pkcs_pss_sha256", "-sha256", 32, :sha256},
    {"rsa_pkcs_pss_sha384", "-sha384", 48, :sha384},
    {"rsa_pkcs_pss_sha512", "-sha512", 64, :sha512}
  ]

  describe "sign pre-hashed data with RSA PSS mechanisms and verify" do
    Enum.each(@rsa_pss_algs2, fn {p11_alg, openssl_digest_alg, salt_len, hash_alg} ->
      test "#{p11_alg} hash #{hash_alg}", context do

        data = :crypto.strong_rand_bytes(8192)
        digest = :crypto.hash(unquote(hash_alg), data)
        suffix = "#{unquote(p11_alg)}_#{unquote(hash_alg)}"

        data_file = Path.join(System.tmp_dir!(), "data_#{suffix}.bin")
        File.write!(data_file, data)
        # input data was already hashed outside of P11exCli
        digest_file = Path.join(System.tmp_dir!(), "digest_#{suffix}.bin")
        File.write!(digest_file, digest)

        sig_file = Path.join(System.tmp_dir!(), "sig_#{suffix}.bin")

        on_exit(fn ->
          File.rm(data_file)
          File.rm(digest_file)
          File.rm(sig_file)
        end)

        output = capture_io(fn ->
          P11exCli.Sign.main(context.token_args ++ [unquote(p11_alg), "none", "label:rsa_4096", digest_file, sig_file])
        end)

        assert output =~ ~r/Signature written to: #{sig_file}/
        assert File.exists?(sig_file)

        OpenSSL.verify(:pss, context.rsa_pubk_file, sig_file, data_file, unquote(openssl_digest_alg), unquote(salt_len))
      end
    end)
  end

  @pkcs15_algs_unhashed [
    {"rsa_pkcs", :sha, "-sha1"},
    {"rsa_pkcs", :sha256, "-sha256"},
    {"rsa_pkcs", :sha384, "-sha384"},
    {"rsa_pkcs", :sha512, "-sha512"}
  ]

  describe "sign unhashed data with RSA PKCS#1 v1.5 mechanisms and verify" do
    Enum.each(@pkcs15_algs_unhashed, fn {p11_alg, digest_alg, openssl_digest_alg} ->
      test "#{p11_alg} hash #{digest_alg}", context do

        data = :crypto.strong_rand_bytes(8192)
        suffix = "#{unquote(p11_alg)}_#{unquote(digest_alg)}"

        data_file = Path.join(System.tmp_dir!(), "data_#{suffix}.bin")
        File.write!(data_file, data)

        sig_file = Path.join(System.tmp_dir!(), "sig_#{suffix}.bin")

        on_exit(fn ->
          File.rm(data_file)
          File.rm(sig_file)
        end)

        output = capture_io(fn ->
          P11exCli.Sign.main(context.token_args ++ [unquote(p11_alg), Atom.to_string(unquote(digest_alg)), "label:rsa_4096", data_file, sig_file])
        end)

        assert output =~ ~r/Signature written to: #{sig_file}/
        assert File.exists?(sig_file)

        OpenSSL.verify(:pkcs15, context.rsa_pubk_file, sig_file, data_file, unquote(openssl_digest_alg))
      end
    end)
  end

  @pkcs15_algs_prehashed [
    {"rsa_pkcs_sha1", :sha, "-sha1"},
    {"rsa_pkcs_sha224", :sha224, "-sha224"},
    {"rsa_pkcs_sha256", :sha256, "-sha256"},
    {"rsa_pkcs_sha384", :sha384, "-sha384"},
    {"rsa_pkcs_sha512", :sha512, "-sha512"}
  ]

  describe "sign already hashed data with RSA PKCS#1 v1.5 mechanisms and verify" do
    Enum.each(@pkcs15_algs_prehashed, fn {p11_alg, digest_alg, openssl_digest_alg} ->
      test "#{p11_alg} hash #{digest_alg}", context do

        data = :crypto.strong_rand_bytes(8192)
        digest = :crypto.hash(unquote(digest_alg), data)
        suffix = "#{unquote(p11_alg)}_#{unquote(digest_alg)}"

        data_file = Path.join(System.tmp_dir!(), "data_#{suffix}.bin")
        File.write!(data_file, data)

        # input data was already hashed outside of P11exCli
        digest_file = Path.join(System.tmp_dir!(), "digest_#{suffix}.bin")
        File.write!(digest_file, digest)

        sig_file = Path.join(System.tmp_dir!(), "sig_#{suffix}.bin")

        on_exit(fn ->
          File.rm(data_file)
          File.rm(digest_file)
          File.rm(sig_file)
        end)

        output = capture_io(fn ->
          P11exCli.Sign.main(context.token_args ++ [unquote(p11_alg), "none", "label:rsa_4096", digest_file, sig_file])
        end)

        assert output =~ ~r/Signature written to: #{sig_file}/
        assert File.exists?(sig_file)

        OpenSSL.verify(:pkcs15, context.rsa_pubk_file, sig_file, digest_file, unquote(openssl_digest_alg))
      end
    end)
  end

end
