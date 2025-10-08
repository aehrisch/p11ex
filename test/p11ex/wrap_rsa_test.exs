defmodule P11exTest.WrapRsa do

  use ExUnit.Case, async: false

  alias P11ex.Session, as: Session


  @moduledoc """
  This module contains tests that use RSA wrapping mechanisms to wrap and unwrap keys.
  """

  @moduletag :wrap

  setup_all do
    P11ex.TestHelper.setup_session()
  end

  @wrap_mechanisms [
    {:ckm_rsa_pkcs},
    {:ckm_rsa_pkcs_oaep, %{hash_alg: :sha, mgf_hash_alg: :sha}}
  ]

  for wm <- @wrap_mechanisms do

    test "use #{inspect(wm)} to wrap and unwrap a AES key", context do
      wrapping_mechanism = unquote(Macro.escape(wm))

      {wrap_pubk, wrap_prvk} = KeyWrappingTestHelper.gen_rsa_wrapping_key(context.session_pid)

      key_id = :crypto.strong_rand_bytes(16)
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
          Session.wrap_key(context.session_pid, wrapping_mechanism, wrap_pubk, key)

        assert byte_size(wrapped_key) > 0 and byte_size(wrapped_key) <= 1024
        Session.destroy_object(context.session_pid, key)

        {:ok, unwrapped_key} = Session.unwrap_key(
          context.session_pid,
          wrapping_mechanism,
          wrap_prvk, wrapped_key,
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

        [unwrapped_key, wrap_prvk, wrap_pubk]
          |> Enum.each(fn obj -> Session.destroy_object(context.session_pid, obj) end)
    end
  end

  for wm <- @wrap_mechanisms do

    test "use #{inspect(wm)} to wrap and unwrap a RSA private key", context do
      wrapping_mechanism = unquote(Macro.escape(wm))

      {wrap_pubk, wrap_prvk} = KeyWrappingTestHelper.gen_rsa_wrapping_key(context.session_pid)

      key_id = :crypto.strong_rand_bytes(16)
      # generate an extractable key that will be wrapped
      {:ok, key} = Session.generate_key(
        context.session_pid,
        {:ckm_aes_key_gen},
        [
          {:cka_token, false},
          {:cka_label, "key_to_wrap"},
          {:cka_value_len, 32},
          {:cka_id, key_id},
          {:cka_extractable, true}
        ])

      # compute KCV of the key and capture attributes
      {:ok, kcv_before} = CryptoTestHelper.compute_kcv(context.session_pid, key)
      {:ok, attribs_before, []} = Session.read_object(context.session_pid, key, P11ex.Lib.ObjectAttributes.secret_key())

      # wrap the key
      {:ok, wrapped_key} =
        Session.wrap_key(context.session_pid, wrapping_mechanism, wrap_pubk, key)

      # delete the key
      Session.destroy_object(context.session_pid, key)

      # unwrap the key
      {:ok, unwrapped_key} =
        Session.unwrap_key(context.session_pid,
          wrapping_mechanism, wrap_prvk, wrapped_key,
          [{:cka_token, false},
          {:cka_class, :cko_secret_key},
          {:cka_label, "uwnrapped_key"},
          {:cka_class, :cko_secret_key},
          {:cka_id, key_id},
          {:cka_key_type, :ckk_aes}])

      # compute KCV of the unwrapped key
      {:ok, kcv_after} = CryptoTestHelper.compute_kcv(context.session_pid, unwrapped_key)
      {:ok, attribs_after, []} = Session.read_object(context.session_pid, unwrapped_key, P11ex.Lib.ObjectAttributes.secret_key())

      assert kcv_before == kcv_after
      assert attribs_after.cka_label == "uwnrapped_key"
      assert attribs_after.cka_token == false
      assert attribs_before.cka_key_type == attribs_after.cka_key_type
      assert attribs_before.cka_class == attribs_after.cka_class
      assert attribs_before.cka_id == attribs_after.cka_id

      Session.destroy_object(context.session_pid, unwrapped_key)

      Session.destroy_object(context.session_pid, wrap_pubk)
      Session.destroy_object(context.session_pid, wrap_prvk)
    end
  end

end
