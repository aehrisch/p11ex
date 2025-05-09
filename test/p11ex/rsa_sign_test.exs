defmodule P11ExTest.RsaSign do

  use ExUnit.Case, async: false

  alias P11ex.Lib, as: Lib
  alias P11ex.Session, as: Session

  @moduletag :rsa
  @moduletag :rsa_sign
  @moduletag :softhsm

  setup_all do
    P11ex.TestHelper.setup_session()
  end

  test "sign CKM_RSA_PKCS", context do
    {pubk, prvk} = P11exRSATestHelper.gen_keypair(context.session_pid)

    # read the public key and make a public key record useable with the Erlang public_key module
    {:ok, pubk_attrs, []} = Session.read_object(context.session_pid, pubk, Lib.ObjectAttributes.rsa_public_key())
    rsa_pub_key = {:RSAPublicKey, pubk_attrs[:cka_modulus], pubk_attrs[:cka_public_exponent]}

    data = :crypto.strong_rand_bytes(64)

    mechanisms = [
      {:ckm_rsa_pkcs, :none},
      {:ckm_sha1_rsa_pkcs, :sha},
      {:ckm_sha224_rsa_pkcs, :sha224},
      {:ckm_sha256_rsa_pkcs, :sha256},
      {:ckm_sha384_rsa_pkcs, :sha384},
      {:ckm_sha512_rsa_pkcs, :sha512}
    ]

    # loop through the mechanisms and sign the data, and verify the signature
    mechanisms
    |> Enum.each(fn {m, d} ->
      :ok = Session.sign_init(context.session_pid, {m}, prvk)

      assert {:ok, signature} =
        Session.sign(context.session_pid, data)

      assert :public_key.verify(data, d, signature, rsa_pub_key) == true
    end)

    Session.destroy_object(context.session_pid, pubk)
    Session.destroy_object(context.session_pid, prvk)
  end

  test "sign CKM_RSA_PKCS_PSS", context do
    {pubk, prvk} = P11exRSATestHelper.gen_keypair(context.session_pid)

    # read the public key and make a public key record useable with the Erlang public_key module
    {:ok, pubk_attrs, []} = Session.read_object(context.session_pid, pubk, Lib.ObjectAttributes.rsa_public_key())
    rsa_pub_key = {:RSAPublicKey, pubk_attrs[:cka_modulus], pubk_attrs[:cka_public_exponent]}


    mechanisms = [
#      {:ckm_sha1_rsa_pkcs_pss},
#      {:ckm_sha224_rsa_pkcs_pss},
#      {:ckm_sha256_rsa_pkcs_pss},
#      {:ckm_sha384_rsa_pkcs_pss},
#      {:ckm_sha512_rsa_pkcs_pss}
      {:ckm_rsa_pkcs_pss, %{salt_len: 20, hash_alg: :sha, mgf_hash_alg: :sha}},
      {:ckm_rsa_pkcs_pss, %{salt_len: 28, hash_alg: :sha224, mgf_hash_alg: :sha224}},
      {:ckm_rsa_pkcs_pss, %{salt_len: 32, hash_alg: :sha256, mgf_hash_alg: :sha256}},
      {:ckm_rsa_pkcs_pss, %{salt_len: 48, hash_alg: :sha384, mgf_hash_alg: :sha384}},
      {:ckm_rsa_pkcs_pss, %{salt_len: 64, hash_alg: :sha512, mgf_hash_alg: :sha512}}
    ]

    mechanisms
    |> Enum.each(fn m ->
      :ok = Session.sign_init(context.session_pid, m, prvk)

      {_n, params} = m
      data = :crypto.strong_rand_bytes(params.salt_len)

      assert {:ok, signature} =
        Session.sign(context.session_pid, data)

      assert :ok = Session.verify_init(context.session_pid, m, pubk)
      assert :ok = Session.verify(context.session_pid, data, signature)

    end)

    Session.destroy_object(context.session_pid, pubk)
    Session.destroy_object(context.session_pid, prvk)
  end


end
