defmodule P11SoftHsmTest do
  use ExUnit.Case

  @module_path System.get_env("PKCS11_MODULE") ||
                raise "Environment variable PKCS11_MODULE is not set."

  test "failing load_module" do
    # path does not exist
    assert P11ex.load_module("/does/not/exist") == {:error, :dlopen_failed}
  end

  test "happy path" do

    # load the module
    assert {:ok, module} = P11ex.load_module(@module_path)
    assert is_map(module)
    assert module.__struct__ == P11ex.Module
    assert module.path == @module_path
    assert is_reference(module.p11_module)

    # list the slots
    assert {:ok, slots} = P11ex.list_slots(module, true)
    assert is_list(slots)
    assert length(slots) == 2

    IO.inspect(slots, charlists: :as_lists)
  end

end
