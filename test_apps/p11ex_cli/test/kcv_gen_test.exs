defmodule P11exCli.KcvGenTest do

  use ExUnit.Case, async: false
  import ExUnit.CaptureIO

  alias P11exCli.TestHelper, as: TH

  setup_all do
    TH.setup_all()
  end

  describe "kcv-gen" do

    test "happy path with text output", context do
      output = capture_io(fn ->
        key_names = ["label:aes_128", "label:aes_192", "label:aes_256"]
        P11exCli.KcvGen.main(context.token_args ++ key_names)
      end)
      assert output =~ ~r/Key reference: label:aes_128/
      assert output =~ ~r/Key reference: label:aes_192/
      assert output =~ ~r/Key reference: label:aes_256/
    end

    test "happy path with JSON output", context do
      output = capture_io(fn ->
        key_names = ["label:aes_128", "label:aes_192", "label:aes_256"]
        P11exCli.KcvGen.main(context.token_args ++ key_names ++ ["-f", "json"])
      end)
      assert {:ok, r} = Jason.decode(output)
      assert length(r) == 3
    end

    test "show usage", context do
      output = capture_io(fn ->
        P11exCli.main(["help", "kcv-gen"])
      end)

      assert output =~ ~r/Arguments\n/
      assert output =~ ~r/Options\n/
      assert output =~ ~r/\-\-token\-label/
      assert output =~ ~r/\-\-output\-format/
    end

    test "missing key reference", context do
      output = capture_io(fn ->
        assert_raise RuntimeError, fn ->
          P11exCli.KcvGen.main(context.token_args)
        end
      end)
      assert output =~ ~r/Error parsing arguments:/
    end

  end
end
