defmodule P11ex.YubikeyECSignTest do
  use ExUnit.Case, async: false

  alias P11ex.Session, as: Session

  @moduletag :ec_sign
  @moduletag :yubikey

  setup_all do
    {:ok, context} = YubikeyTestHelper.setup_session()
    {:ok, context}
  end

  test "sign and verify EC signature, pre-computed digest", %{session_pid: session_pid} = context do

    data = :crypto.strong_rand_bytes(1024)
    digest = :crypto.hash(:sha256, data)

    # search for private key
    prvk_templ = [
      {:cka_token, true},
      {:cka_private, true},
      {:cka_key_type, :ckk_ec},
      {:cka_class, :cko_private_key},
      {:cka_id, <<0x01>>}
    ]
    {:ok, [prvk]} = Session.find_objects(session_pid, prvk_templ, 2)

    # search for public key
    pubk_templ = [
      {:cka_token, true},
      {:cka_key_type, :ckk_ec},
      {:cka_class, :cko_public_key},
      {:cka_id, <<0x01>>}
    ]
    {:ok, [pubk]} = Session.find_objects(session_pid, pubk_templ, 2)

    # sign some data
    :ok = Session.sign_init(session_pid, {:ckm_ecdsa}, prvk)
    {:ok, signature} = Session.sign(session_pid, digest)

    # verify the signature
    assert :ok = Session.verify_init(context.session_pid, {:ckm_ecdsa}, pubk)
    assert :ok = Session.verify(context.session_pid, digest, signature)
  end

  test "sign and verify EC signature, digest computed by the token", %{session_pid: session_pid} = context do

    data = :crypto.strong_rand_bytes(10_000)

    # search for private key
    prvk_templ = [
      {:cka_token, true},
      {:cka_private, true},
      {:cka_key_type, :ckk_ec},
      {:cka_class, :cko_private_key},
      {:cka_id, <<0x01>>}
    ]
    {:ok, [prvk]} = Session.find_objects(session_pid, prvk_templ, 2)

    # search for public key
    pubk_templ = [
      {:cka_token, true},
      {:cka_key_type, :ckk_ec},
      {:cka_class, :cko_public_key},
      {:cka_id, <<0x01>>}
    ]
    {:ok, [pubk]} = Session.find_objects(session_pid, pubk_templ, 2)

    algorithms = [
      :ckm_ecdsa_sha1,
      :ckm_ecdsa_sha224,
      :ckm_ecdsa_sha256,
      :ckm_ecdsa_sha384,
      :ckm_ecdsa_sha512
    ]

    algorithms
      |> Enum.each(fn algorithm ->
        :ok = Session.sign_init(session_pid, {algorithm}, prvk)
        {:ok, signature} = Session.sign(session_pid, data)

        assert :ok = Session.verify_init(context.session_pid, {algorithm}, pubk)
        assert :ok = Session.verify(context.session_pid, data, signature)

    end)
  end

end
