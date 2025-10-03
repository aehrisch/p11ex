defmodule P11exCli.CommonTest do
  use ExUnit.Case
  alias P11exCli.Common

  test "attrib_for_ref" do
    assert Common.attrib_for_ref("label:test") == {:cka_label, "test"}
    assert Common.attrib_for_ref("id:1234567890") == {:cka_id, <<184, 165, 134, 192, 134, 192, 134, 192>>}
    assert Common.attrib_for_ref("handle:1234567890") == {:cka_handle, 1234567890}
    assert Common.attrib_for_ref("invalid") == {:error, "Invalid reference format"}
  end

end
