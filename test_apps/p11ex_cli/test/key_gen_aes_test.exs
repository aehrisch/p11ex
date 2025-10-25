defmodule P11exCli.KeyGenAesTest do

  use ExUnit.Case, async: false
  import ExUnit.CaptureIO

  alias P11exCli.TestHelper, as: TH

  setup_all do
    TH.setup_all()
  end

  describe "key-gen-aes" do

    test "standard permissions", context do
      label = "l" <> (:rand.uniform(1000000) |> Integer.to_string(16))
      output = capture_io(fn ->
        P11exCli.KeyGenAes.main(context.token_args ++ ["-v", "label", "128"])
      end)

      assert output =~ ~r/Generated new key ID:/
    end

    test "specify key-id", context do
      label = "l" <> (:rand.uniform(1000000) |> Integer.to_string(16))
      key_id = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
      output = capture_io(fn ->
        P11exCli.KeyGenAes.main(context.token_args ++ [label, "128", "--key-id", key_id])
      end)

      assert output =~ ~r/Key generated. Object handle:/
    end
  end

  test "invalid key length", context do
    output = capture_io(fn ->
      assert_raise RuntimeError, fn ->
        P11exCli.KeyGenAes.main(context.token_args ++ ["-v", "label", "127"])
      end
    end)
    assert output =~ ~r/Invalid key length/
  end

  test "show usage", context do
    output = capture_io(fn ->
      P11exCli.main(["help", "key-gen-aes"])
    end)

    assert output =~ ~r/Arguments\n/
    assert output =~ ~r/Options\n/
    assert output =~ ~r/\-\-token\-label/
    assert output =~ ~r/\-\-key\-id/
  end

end
