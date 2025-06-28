defmodule P11ExTest.AttrTest do

  use ExUnit.Case, async: false

  alias P11ex.Session, as: Session

  @moduletag :attr

  setup_all do
    P11ex.TestHelper.setup_session()
  end

  test "attibute: cka_class with wrong argument", context do
    {:error, :invalid_attribute_value, :cka_class} =
      Session.find_objects(context.session_pid, [{:cka_class, "pubk"}], 10)
  end

end
