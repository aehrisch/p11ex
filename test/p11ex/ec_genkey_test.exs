defmodule P11exTest.ECGenKey do

  use ExUnit.Case, async: false

  alias P11ex.Lib, as: Lib
  alias P11ex.Session, as: Session

  @moduletag :ec
  @moduletag :softhsm

  setup_all do
    P11ex.TestHelper.setup_session()
  end

  @tag :ec_genkey
  test "generate_key_pair", context do

    mechanism = {:ckm_ec_key_pair_gen}

    {:ok, params} = P11ex.ECParam.ec_params_from_named_curve(:secp256r1)

    pubk_template = [
      {:cka_token, false},
      {:cka_key_type, :ckk_ec},
      {:cka_verify, true},
      {:cka_label, "pubk-ec_test"},
      {:cka_ec_params, params}
    ]

    prvk_template = [
      {:cka_token, false},
      {:cka_key_type, :ckk_ec},
      {:cka_sign, true},
      {:cka_label, "prvk-ec_test"}
    ]

    assert {:ok, {pubk, prvk}} =
      Session.generate_key_pair(context.session_pid,
      mechanism,
      pubk_template, prvk_template)

    assert pubk.handle != prvk.handle

    assert %Lib.ObjectHandle{} = pubk
  end

end
