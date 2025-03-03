defmodule P11FailureTest do

  use ExUnit.Case

  test "failing load_module" do
    # path does not exist
    assert {:error, :dlopen_failed, _err_msg} = P11ex.Lib.load_module("/does/not/exist")
  end

end
