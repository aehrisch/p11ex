defmodule P11exTest.WrapAes do

  use ExUnit.Case, async: false

  alias P11ex.Lib, as: Lib
  alias P11ex.Session, as: Session

  @moduledoc """
  This module contains tests that use AES-CBC-PAD to wrap and unwrap keys.
  """

  @moduletag :wrap

  setup_all do
    P11ex.TestHelper.setup_session()
  end

  test "use AES-CBC-PAD to wrap and unwrap AES key", context do

    wrapping_key = KeyWrappingTestHelper.gen_aes_wrapping_key(context.session_pid)

    {:ok, key} = Session.generate_key(
      context.session_pid,
      {:ckm_aes_key_gen},
      [
        {:cka_token, false},
        {:cka_label, "key_to_wrap"},
        {:cka_value_len, 32},
        {:cka_extractable, true}
      ])

      # compute KCV of the key
      {:ok, kcv_before} = CryptoTestHelper.compute_kcv(context.session_pid, key)

      {:ok, wrapped_key} =
        Session.wrap_key(context.session_pid,
        {:ckm_aes_key_wrap_pad},
        wrapping_key, key)

      assert byte_size(wrapped_key) > 0 and byte_size(wrapped_key) <= 64
      Session.destroy_object(context.session_pid, key)

      {:ok, unwrapped_key} = Session.unwrap_key(
        context.session_pid,
        {:ckm_aes_key_wrap_pad},
        wrapping_key, wrapped_key,
        [{:cka_token, false},
        {:cka_class, :cko_secret_key},
        {:cka_label, "uwnrapped_key"},
        {:cka_class, :cko_secret_key},
        {:cka_key_type, :ckk_aes}])

      {:ok, kcv_after} = CryptoTestHelper.compute_kcv(context.session_pid, unwrapped_key)
      assert kcv_before == kcv_after

      {:ok, attribs, []} = Session.read_object(context.session_pid, unwrapped_key,
          [:cka_token, :cka_class, :cka_label, :cka_key_type])
      assert attribs.cka_label == "uwnrapped_key"
      assert attribs.cka_key_type == :ckk_aes
      assert attribs.cka_token == false
      assert attribs.cka_class == :cko_secret_key

    Session.destroy_object(context.session_pid, unwrapped_key)
    Session.destroy_object(context.session_pid, wrapping_key)
  end

  test "use AES-CBC-PAD to wrap and unwrap a RSA private key", context do

    wrapping_key = KeyWrappingTestHelper.gen_aes_wrapping_key(context.session_pid)
    {pubk, prvk}  = RSATestHelper.gen_keypair(context.session_pid, true)

    {:ok, orig_attribs, []} = Session.read_object(context.session_pid, prvk, Lib.ObjectAttributes.rsa_private_key())

    {:ok, wrapped_key} =
      Session.wrap_key(context.session_pid,
      {:ckm_aes_key_wrap_pad},
      wrapping_key, prvk)

    assert byte_size(wrapped_key) > 0 and byte_size(wrapped_key) <= 4096

    Session.destroy_object(context.session_pid, prvk)
    Session.destroy_object(context.session_pid, pubk)

    key_id = :crypto.strong_rand_bytes(16)
    {:ok, unwrapped_key} = Session.unwrap_key(
      context.session_pid,
      {:ckm_aes_key_wrap_pad},
      wrapping_key, wrapped_key,
      [{:cka_token, false},
        {:cka_class, :cko_private_key},
        {:cka_label, "uwnrapped_key"},
        {:cka_key_type, :ckk_rsa},
        {:cka_id, key_id},
        {:cka_sign, true},
        {:cka_decrypt, true}])

    {:ok, unwrapped_attribs, []} = Session.read_object(context.session_pid, unwrapped_key, Lib.ObjectAttributes.rsa_private_key())

    assert unwrapped_attribs.cka_token == false
    assert unwrapped_attribs.cka_class == :cko_private_key
    assert unwrapped_attribs.cka_label == "uwnrapped_key"
    assert unwrapped_attribs.cka_key_type == :ckk_rsa
    assert unwrapped_attribs.cka_sign == true
    assert unwrapped_attribs.cka_decrypt == true

    assert unwrapped_attribs.cka_never_extractable == false
    assert unwrapped_attribs.cka_local == false
    assert unwrapped_attribs.cka_id == key_id

    assert unwrapped_attribs.cka_modulus == orig_attribs.cka_modulus
    assert unwrapped_attribs.cka_public_exponent == orig_attribs.cka_public_exponent

    Session.destroy_object(context.session_pid, unwrapped_key)
  end

  test "use AES-CBC-PAD to wrap and unwrap a EC private key", context do

    wrapping_key = KeyWrappingTestHelper.gen_aes_wrapping_key(context.session_pid)
    {pubk, prvk}  = ECSignTestHelper.gen_keypair(context.session_pid, :secp256r1, true)

    {:ok, orig_attribs, []} = Session.read_object(context.session_pid, prvk, Lib.ObjectAttributes.ec_private_key())

    {:ok, wrapped_key} =
      Session.wrap_key(context.session_pid,
      {:ckm_aes_key_wrap_pad},
      wrapping_key, prvk)

    assert byte_size(wrapped_key) > 0 and byte_size(wrapped_key) <= 4096

    Session.destroy_object(context.session_pid, prvk)
    Session.destroy_object(context.session_pid, pubk)

    key_id = :crypto.strong_rand_bytes(16)
    {:ok, unwrapped_key} = Session.unwrap_key(
      context.session_pid,
      {:ckm_aes_key_wrap_pad},
      wrapping_key, wrapped_key,
      [{:cka_token, false},
        {:cka_class, :cko_private_key},
        {:cka_label, "uwnrapped_key"},
        {:cka_key_type, :ckk_ec},
        {:cka_id, key_id},
        {:cka_sign, true}])

    {:ok, unwrapped_attribs, []} = Session.read_object(context.session_pid, unwrapped_key, Lib.ObjectAttributes.ec_private_key())

    assert unwrapped_attribs.cka_token == false
    assert unwrapped_attribs.cka_class == :cko_private_key
    assert unwrapped_attribs.cka_label == "uwnrapped_key"
    assert unwrapped_attribs.cka_key_type in [:ckk_ec, :ckk_ecdsa]
    assert unwrapped_attribs.cka_sign == true
    assert unwrapped_attribs.cka_id == key_id
    assert unwrapped_attribs.cka_ec_params == orig_attribs.cka_ec_params

    Session.destroy_object(context.session_pid, unwrapped_key)
  end


end
