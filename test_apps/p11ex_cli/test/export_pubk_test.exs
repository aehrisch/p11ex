defmodule P11exCli.ExportPubkTest do

  use ExUnit.Case, async: false
  import ExUnit.CaptureIO

  alias P11exCli.TestHelper, as: TH

  setup_all do
    TH.setup_all()
  end

  describe "export-pubk" do

    test "no arguments" do
      output = capture_io(:stderr, fn ->
        assert_raise RuntimeError, "halt-error", fn ->
          P11exCli.ExportPubk.main([])
        end
      end)
      assert output =~ "Error parsing arguments:"
    end

    test "show usage" do
      output = capture_io(fn ->
        P11exCli.main(["help", "export-pubk"])
      end)
      assert output =~ ~r/Arguments\n/
      assert output =~ ~r/Options\n/
    end

    test "export RSA public key", context do
      pem_data = capture_io(fn ->
        P11exCli.ExportPubk.main(context.token_args ++ ["label:rsa_4096"])
      end)

      # must contain PEM header and footer
      assert pem_data =~ ~r/-----BEGIN PUBLIC KEY-----/
      assert pem_data =~ ~r/-----END PUBLIC KEY-----/

      # Verify it can be parsed by public_key module
      entries = :public_key.pem_decode(pem_data)
      assert is_list(entries) and length(entries) == 1
      assert {:"SubjectPublicKeyInfo", der, _} = Enum.at(entries, 0)

      # Decode and verify it's an RSA key
      {:"RSAPublicKey", mod, 65537} = :public_key.pem_entry_decode(Enum.at(entries, 0))
      assert is_integer(mod) and mod > 0
    end

    test "export EC public key", context do
      pem_data = capture_io(fn ->
        P11exCli.ExportPubk.main(context.token_args ++ ["label:ecdsa_p256"])
      end)

      # must contain PEM header and footer
      assert pem_data =~ ~r/-----BEGIN PUBLIC KEY-----/
      assert pem_data =~ ~r/-----END PUBLIC KEY-----/

      # Verify it can be parsed by public_key module
      entries = :public_key.pem_decode(pem_data)
      assert is_list(entries) and length(entries) == 1
      assert {:"SubjectPublicKeyInfo", der, _} = Enum.at(entries, 0)

      # Decode and verify it's an EC key
      {{:ECPoint, ec_point}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}} = :public_key.pem_entry_decode(Enum.at(entries, 0))
      assert is_binary(ec_point)
    end

    test "export with invalid key reference", context do
      output = capture_io(:stderr, fn ->
        assert_raise RuntimeError, "halt-error", fn ->
          P11exCli.ExportPubk.main(context.token_args ++ ["label:nonexistent_key"])
        end
      end)
      assert output =~ ~r/Key not found/
    end

  end

end
