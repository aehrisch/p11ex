defmodule P11SoftHsmTest do
  use ExUnit.Case

  @module_path System.get_env("PKCS11_MODULE") ||
                raise "Environment variable PKCS11_MODULE is not set."

  test "failing load_module" do
    # path does not exist
    assert {:error, :dlopen_failed, _err_msg} = P11ex.Lib.load_module("/does/not/exist")
  end

  test "happy path" do

    # load the module
    assert {:ok, module} = P11ex.Lib.load_module(@module_path)
    assert is_map(module)
    assert module.__struct__ == P11ex.Lib.Module
    assert module.path == @module_path
    assert is_reference(module.p11_module)

    # list the slots
    assert {:ok, slots} = P11ex.Lib.list_slots(module, true)
    assert is_list(slots)
    assert length(slots) == 2

    IO.inspect(slots)

    assert {:ok, token_info} = P11ex.Lib.token_info(module, Enum.at(slots, 1).slot_id)
    IO.inspect(token_info)
    assert is_map(token_info)
    assert token_info.label == "test"
    assert token_info.manufacturer_id == "SoftHSM"
    assert token_info.model == "SoftHSM"

  end

end
