defmodule P11ExTest.RsaGenKey do

  use ExUnit.Case, async: false

  alias P11ex.Lib, as: Lib
  alias P11ex.Module, as: Module
  alias P11ex.Session, as: Session

  @moduletag :rsa
  @moduletag :softhsm
  
  setup_all do
    P11ex.TestHelper.setup_session()
  end

  @tag :rsa_genkey
  test "generate_key_pair", context do

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
      Session.generate_key_pair(context.session_pid,
      {:ckm_rsa_pkcs_key_pair_gen},
      pubk_template, prvk_template)

    assert pubk.handle != prvk.handle

    # Verify pubk is an ObjectHandle struct
    assert %Lib.ObjectHandle{} = pubk
    assert is_integer(pubk.handle) and pubk.handle > 0

    # Verify prvk is an ObjectHandle struct
    assert %Lib.ObjectHandle{} = prvk
    assert is_integer(prvk.handle) and prvk.handle > 0

    # Check pubk attributes
    {:ok, pubk_attribs, []} = Session.read_object(context.session_pid, pubk, Lib.ObjectAttributes.rsa_public_key())

    assert pubk_attribs[:cka_class] == :cko_public_key
    assert pubk_attribs[:cka_key_type] == :ckk_rsa
    assert pubk_attribs[:cka_label] == "rsa_test_key"
    assert pubk_attribs[:cka_modulus_bits] == 2048
    assert pubk_attribs[:cka_public_exponent] == 65537
    assert pubk_attribs[:cka_token] == false
    assert pubk_attribs[:cka_encrypt] == true
    assert pubk_attribs[:cka_verify] == true
    assert pubk_attribs[:cka_local] == true
    assert pubk_attribs[:cka_derive] == false

    # not set, so should be inaccessible
    assert pubk_attribs[:cka_start_date] == :inaccessible
    assert pubk_attribs[:cka_end_date] == :inaccessible
    assert pubk_attribs[:cka_id] == :inaccessible

    # Check prvk attributes
    {:ok, prvk_attribs, []} = Session.read_object(context.session_pid, prvk, Lib.ObjectAttributes.rsa_private_key())

    assert prvk_attribs[:cka_class] == :cko_private_key
    assert prvk_attribs[:cka_key_type] == :ckk_rsa
    assert prvk_attribs[:cka_private] == true
    assert prvk_attribs[:cka_token] == false
    assert prvk_attribs[:cka_derive] == false
    assert prvk_attribs[:cka_local] == true
    assert prvk_attribs[:cka_always_sensitive] == true
    assert prvk_attribs[:cka_decrypt] == true
    assert prvk_attribs[:cka_extractable] == false
    assert prvk_attribs[:cka_never_extractable] == true
    assert prvk_attribs[:cka_sign] == true
    assert prvk_attribs[:cka_unwrap] == true
    assert prvk_attribs[:cka_wrap_with_trusted] == false
    assert prvk_attribs[:cka_modulus] == pubk_attribs[:cka_modulus]
    assert prvk_attribs[:cka_public_exponent] == pubk_attribs[:cka_public_exponent]
    assert prvk_attribs[:cka_always_authenticate] == false
    assert prvk_attribs[:cka_sensitive] == true
    assert prvk_attribs[:cka_sign_recover] == true

    # not set, so should be inaccessible
    assert prvk_attribs[:cka_start_date] == :inaccessible
    assert prvk_attribs[:cka_end_date] == :inaccessible
    assert prvk_attribs[:cka_id] == :inaccessible

    Session.destroy_object(context.session_pid, pubk)
    Session.destroy_object(context.session_pid, prvk)
  end


end
