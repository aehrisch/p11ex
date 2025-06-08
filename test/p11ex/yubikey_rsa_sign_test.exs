defmodule P11ex.YubikeyRSASignTest do
  use ExUnit.Case, async: false

  alias P11ex.Session, as: Session

  @moduletag :rsa_sign
  @moduletag :yubikey

  setup_all do
    {:ok, context} = YubikeyTestHelper.setup_session()
    {:ok, context}
  end

  test "sign and verify RSA signature", %{session_pid: session_pid} = context do

    data = :crypto.strong_rand_bytes(1024)
    digest = :crypto.hash(:sha256, data)

    # search for private key
    prvk_templ = [
      {:cka_token, true},
      {:cka_private, true},
      {:cka_key_type, :ckk_rsa},
      {:cka_class, :cko_private_key},
      {:cka_id, <<0x02>>}
    ]
    {:ok, [prvk]} = Session.find_objects(session_pid, prvk_templ, 2)

    # search for public key
    pubk_templ = [
      {:cka_token, true},
      {:cka_key_type, :ckk_rsa},
      {:cka_class, :cko_public_key},
      {:cka_id, <<0x02>>}
    ]
    {:ok, [pubk]} = Session.find_objects(session_pid, pubk_templ, 2)

    mechanism = {:ckm_rsa_pkcs_pss, %{salt_len: 32, hash_alg: :sha256, mgf_hash_alg: :sha256}}

    :ok = Session.sign_init(session_pid, mechanism, prvk)
    assert {:ok, signature} = Session.sign(context.session_pid, digest)

    assert :ok = Session.verify_init(context.session_pid, mechanism, pubk)
    assert :ok = Session.verify(context.session_pid, digest, signature)
  end

end
