defmodule P11exCli.CommonTest do
  use ExUnit.Case
  alias P11exCli.Common

  describe "attrib_value_to_str" do

    test "string" do
      assert Common.attrib_value_to_str("test") == "0x74657374 [test]"
      assert Common.attrib_value_to_str(<<1, 2, 3, 4>>) == "0x01020304"
      assert Common.attrib_value_to_str(<<200, 170, 60>>) == "0xC8AA3C"
    end

    test "numbers" do
      assert Common.attrib_value_to_str(1) == "1"
      assert Common.attrib_value_to_str(1.0) == "1.0"
      assert Common.attrib_value_to_str(1.0) == "1.0"
    end

    test "boolean" do
      assert Common.attrib_value_to_str(true) == "true"
      assert Common.attrib_value_to_str(false) == "false"
    end
  end

  test "attrib_for_ref" do
    assert Common.attrib_for_ref("label:test") == {:cka_label, "test"}
    #assert Common.attrib_for_ref("id:1234567890") == {:cka_id, <<184, 165, 134, 192, 134, 192, 134, 192>>}
    #assert Common.attrib_for_ref("handle:1234567890") == {:cka_handle, 1234567890}
    #assert Common.attrib_for_ref("invalid") == {:error, "Invalid reference format"}
  end

end
