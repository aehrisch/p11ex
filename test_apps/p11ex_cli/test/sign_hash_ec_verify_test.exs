defmodule P11exCli.SignHashECVerifyTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureIO
  import ExUnit.CaptureLog

  require Logger

  alias P11exCli.TestHelper, as: TH
  alias P11exCli.OpenSSLVerify, as: OpenSSL

  @ec_key_labels ["ecdsa_p256", "ecdsa_p384", "ecdsa_p521"]

  setup_all context do
    context1 = TH.setup_all()

    # export ECDSA public_keys to files
    ec_pubk_files =
      @ec_key_labels
      |> Enum.map(fn label ->
        pubk_file = Path.join(System.tmp_dir!(), "#{label}.pem")
        pem = capture_io(fn ->
          P11exCli.ExportPubk.main(context1.token_args ++ ["label:#{label}"])
        end)
        File.write!(pubk_file, pem)
        Logger.debug("wrote #{label} public key to #{pubk_file}")
        {label, pubk_file}
      end)
      |> Map.new()

    on_exit(fn ->
      @ec_key_labels
      |> Enum.each(fn label ->
        File.rm(Path.join(System.tmp_dir!(), "#{label}.pem"))
      end)
    end)

    Map.merge(context, context1)
      |> Map.merge(%{ec_pubk_files: ec_pubk_files})
  end

  @ecdsa_digest_algs [
    {:sha256, "ecdsa_p256", "-sha256", 32},
    {:sha384, "ecdsa_p384", "-sha384", 48},
    {:sha512, "ecdsa_p521", "-sha512", 64}
  ]

  describe "sign already hashed data with ECDSA mechanisms and verify" do
    Enum.each(@ecdsa_digest_algs, fn {hash_alg, key_label, openssl_dgst, digest_size} ->
      test "sign with #{hash_alg} mechanism and key #{key_label}", context do

        # create data and digest file
        suffix = "#{unquote(key_label)}_#{unquote(hash_alg)}"
        data = :crypto.strong_rand_bytes(8192)
        data_file = Path.join(System.tmp_dir!(), "data_#{suffix}.bin")
        File.write!(data_file, data)

        digest = :crypto.hash(unquote(hash_alg), data)
        digest_file = Path.join(System.tmp_dir!(), "digest_#{suffix}.bin")
        File.write!(digest_file, digest)

        sig_file = Path.join(System.tmp_dir!(), "sig_#{suffix}.bin")

        on_exit(fn ->
          File.rm(data_file)
          File.rm(digest_file)
          File.rm(sig_file)
        end)

        output = capture_io(fn ->
          # plain ECDSA sign without pre-hashing by P11exCli
          P11exCli.Sign.main(context.token_args ++ ["ecdsa_plain", "none", "label:#{unquote(key_label)}", digest_file, sig_file])
        end)

        assert output =~ ~r/Signature written to: #{sig_file}/
        assert File.exists?(sig_file)

        pubk_file = context.ec_pubk_files[unquote(key_label)]
        OpenSSL.verify(:ecdsa, pubk_file, sig_file, data_file, unquote(openssl_dgst))
      end
    end)
  end

  describe "pre-hash and sign with ECDSA mechanisms and verify" do
    Enum.each(@ecdsa_digest_algs, fn {hash_alg, key_label, openssl_dgst, digest_size} ->
      test "sign with #{hash_alg} mechanism and key #{key_label}", context do

        # create data and digest file
        suffix = "#{unquote(key_label)}_#{unquote(hash_alg)}"
        data = :crypto.strong_rand_bytes(8192)
        data_file = Path.join(System.tmp_dir!(), "data_#{suffix}.bin")
        File.write!(data_file, data)

        sig_file = Path.join(System.tmp_dir!(), "sig_#{suffix}.bin")

        on_exit(fn ->
          File.rm(data_file)
          File.rm(sig_file)
        end)

        output = capture_io(fn ->
          # ECDSA sign with pre-hashing by P11exCli
          P11exCli.Sign.main(context.token_args ++ ["ecdsa_plain", Atom.to_string(unquote(hash_alg)), "label:#{unquote(key_label)}", data_file, sig_file])
        end)

        assert output =~ ~r/Signature written to: #{sig_file}/
        assert File.exists?(sig_file)

        pubk_file = context.ec_pubk_files[unquote(key_label)]
        OpenSSL.verify(:ecdsa, pubk_file, sig_file, data_file, unquote(openssl_dgst))
      end
    end)
  end
end
