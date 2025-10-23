defmodule P11exCli.ObjectListTest do

  use ExUnit.Case, async: false
  import ExUnit.CaptureIO

  alias P11exCli.TestHelper, as: TH

  setup_all do
    TH.setup_all()
  end

  describe "object-list happy path with text output" do

    test "listing secret keys", context do
      output = capture_io(fn ->
        P11exCli.ObjectList.main(context.token_args ++ ["seck"])
      end)
      assert output =~ ~r/cka_label:\s+0x[0-9A-F]+\s\[aes_128\]/
      assert output =~ ~r/cka_label:\s+0x[0-9A-F]+\s\[aes_192\]/
      assert output =~ ~r/cka_label:\s+0x[0-9A-F]+\s\[aes_256\]/
    end

    test "listing private keys", context do
      output = capture_io(fn ->
        P11exCli.ObjectList.main(context.token_args ++ ["prvk"])
      end)
      assert output =~ ~r/cka_label:\s+0x[0-9A-F]+\s\[wrapping_rsa\]/
    end

    test "listing public keys", context do
      output = capture_io(fn ->
        P11exCli.ObjectList.main(context.token_args ++ ["pubk"])
      end)
      assert output =~ ~r/cka_class:\s+:cko_public_key/
      assert output =~ ~r/cka_label:\s+0x[0-9A-F]+\s\[wrapping_rsa\]/
    end
  end

  describe "object-list with JSON output" do
    for object_type <- ["pubk", "prvk", "seck"] do
      test "json output for #{object_type}", context do
        object_type = unquote(object_type)
        output = capture_io(fn ->
          P11exCli.ObjectList.main(context.token_args ++ [object_type, "-f", "json"])
        end)
        assert {:ok, _m} = Jason.decode(output)
      end
    end
  end

  describe "object-list wrong arguments" do

    test "wrong object type", context do
      output = capture_io(fn ->
        assert_raise RuntimeError, "halt-error", fn ->
          P11exCli.ObjectList.main(context.token_args ++ ["wrong"])
        end
      end)
      assert output =~ ~r/Invalid object type: wrong/
    end

  end

  test "list-objects, show usage", context do
    output = capture_io(fn ->
      P11exCli.main(["help", "list-objects"])
    end)

    assert output =~ ~r/Arguments\n/
    assert output =~ ~r/Options\n/
    assert output =~ ~r/\-\-token\-label/
    assert output =~ ~r/\-\-output\-format/
  end
end
