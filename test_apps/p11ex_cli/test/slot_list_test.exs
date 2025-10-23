defmodule P11exCli.SlotListTest do

  use ExUnit.Case, async: false
  import ExUnit.CaptureIO

  alias P11exCli.TestHelper, as: TH

  setup_all do
    TH.setup_all()
  end

  describe "slot-list" do

    test "no options", context do
      output = capture_io(fn ->
        P11exCli.SlotList.main(context.module_args)
      end)

      assert output =~ ~r/Slot 1:/
      assert output =~ ~r/Slot\s+[0-9]+:/
    end

    test "with-token set to true", context do
      output = capture_io(fn ->
        P11exCli.SlotList.main(context.module_args ++ ["-t"])
      end)

      assert output =~ ~r/Slot 1:/
      assert output =~ ~r/Slot\s+[0-9]+:/
    end
  end

  test "list-slots, show usage" do
    output = capture_io(fn ->
      P11exCli.main(["help", "list-slots"])
    end)
    assert output =~ ~r/Options\n/
    assert output =~ ~r/\-\-with\-token/
  end

end
