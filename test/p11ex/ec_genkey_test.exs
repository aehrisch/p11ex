defmodule P11exTest.ECGenKey do

  use ExUnit.Case, async: false

  alias P11ex.ECParam, as: ECParam
  alias P11ex.Lib, as: Lib
  alias P11ex.Session, as: Session

  @moduletag :ec
  @moduletag :softhsm

  setup_all do
    P11ex.TestHelper.setup_session()
  end

  @tag :ec_genkey
  test "generate_key_pair", context do

    [:secp256r1, :secp384r1, :secp521r1]
      |> Enum.each(fn curve ->

      key_id = :crypto.strong_rand_bytes(16)

      mechanism = {:ckm_ec_key_pair_gen}

      {:ok, params} = ECParam.ec_params_from_named_curve(curve)

      pubk_template = [
        {:cka_token, false},
        {:cka_key_type, :ckk_ec},
        {:cka_verify, true},
        {:cka_label, "pubk-#{curve}"},
        {:cka_ec_params, params},
        {:cka_id, key_id}
      ]

      prvk_template = [
        {:cka_token, false},
        {:cka_key_type, :ckk_ec},
        {:cka_sign, true},
        {:cka_label, "prvk-#{curve}"},
        {:cka_id, key_id}
      ]

      assert {:ok, {pubk, prvk}} =
        Session.generate_key_pair(context.session_pid,
        mechanism,
        pubk_template, prvk_template)

      assert %Lib.ObjectHandle{} = pubk
      assert %Lib.ObjectHandle{} = prvk
      assert pubk.handle != prvk.handle

      {:ok, pubk_attribs, []} =
        Session.read_object(context.session_pid, pubk,
          Lib.ObjectAttributes.ec_public_key())
      {:ok, prvk_attribs, []} =
        Session.read_object(context.session_pid, prvk,
          Lib.ObjectAttributes.ec_private_key())

      assert is_map(pubk_attribs)
      assert pubk_attribs.cka_label == "pubk-#{curve}"
      assert pubk_attribs.cka_private == false
      assert pubk_attribs.cka_encrypt == true
      assert pubk_attribs.cka_verify == true
      assert pubk_attribs.cka_trusted == false
      assert pubk_attribs.cka_token == false
      assert pubk_attribs.cka_wrap == true
      assert pubk_attribs.cka_id == key_id
      assert pubk_attribs.cka_class == :cko_public_key
      assert pubk_attribs.cka_key_type == :ckk_ecdsa
      assert pubk_attribs.cka_ec_params == params

      assert is_map(prvk_attribs)
      assert prvk_attribs.cka_label == "prvk-#{curve}"
      assert prvk_attribs.cka_private == true
      assert prvk_attribs.cka_decrypt == true
      assert prvk_attribs.cka_sign == true
      assert prvk_attribs.cka_decrypt == true
      assert prvk_attribs.cka_class == :cko_private_key
      assert prvk_attribs.cka_key_type == :ckk_ecdsa
      assert prvk_attribs.cka_ec_params == params

      Session.destroy_object(context.session_pid, pubk)
      Session.destroy_object(context.session_pid, prvk)
    end)
  end

end
