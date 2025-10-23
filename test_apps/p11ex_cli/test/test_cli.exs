defmodule P11exCli.SlotListTest do

  use ExUnit.Case, async: false
  import ExUnit.CaptureIO

  alias P11exCli.TestHelper, as: TH

  setup_all do
    TH.setup_all()
  end

  test "no command, no args" do
    output = capture_io(fn ->
      P11exCli.main([])
    end)

    assert output =~ ~r/Usage: p11ex <subcommand> \[options\]/
    assert output =~ ~r/list-slots/
    assert output =~ ~r/list-objects/
    assert output =~ ~r/key-gen-aes/
    assert output =~ ~r/key-wrap/
    assert output =~ ~r/key-unwrap/
  end

  test "unknown subcommand" do
    output = capture_io(fn ->
      P11exCli.main(["blorf"])
    end)
    assert output =~ ~r/Unknown subcommand: blorf/
  end

end
