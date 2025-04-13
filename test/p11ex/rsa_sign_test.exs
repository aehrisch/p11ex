defmodule P11ExTest.RsaSign do

  use ExUnit.Case, async: false

  alias P11ex.Lib, as: Lib
  alias P11ex.Module, as: Module
  alias P11ex.Session, as: Session

  @moduletag :rsa
  @moduletag :rsa_sign
  @moduletag :softhsm

  setup_all do
    P11ex.TestHelper.setup_session()
  end

  def gen_keypair(session_pid) do

    mechanism = {:ckm_rsa_pkcs_key_pair_gen}

    pubk_template = [
      {:cka_token, false},
      {:cka_encrypt, true},
      {:cka_verify, true},
      {:cka_modulus_bits, 2048},
      {:cka_public_exponent, 65537},
      {:cka_label, "rsa_test_key"}
    ]

    prvk_template = [
      {:cka_token, false},
      {:cka_private, true},
      {:cka_sensitive, true},
      {:cka_decrypt, true},
      {:cka_sign, true},
      {:cka_label, "rsa_test_key"}
    ]

    assert {:ok, {pubk, prvk}} =
      Session.generate_key_pair(session_pid,
      {:ckm_rsa_pkcs_key_pair_gen},
      pubk_template, prvk_template)
    {pubk, prvk}
  end

  test "sign CKM_RSA_PKCS", context do
    {pubk, prvk} = gen_keypair(context.session_pid)

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
  end


end
