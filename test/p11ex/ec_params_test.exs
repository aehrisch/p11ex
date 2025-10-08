defmodule P11ex.ECParamsTest do
  use ExUnit.Case

  @moduletag :ec
  @moduletag :asn1

  @curves [
    {:secp192r1, {1, 2, 840, 10_045, 3, 1, 1}, <<0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01>>},
    {:secp224r1, {1, 3, 132, 0, 33}, <<0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21>>},
    {:secp256r1, {1, 2, 840, 10_045, 3, 1, 7}, <<0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07>>},
    {:secp384r1, {1, 3, 132, 0, 34}, <<0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22>>},
    {:secp521r1, {1, 3, 132, 0, 35}, <<0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23>>},
    {:brainpoolP256r1, {1, 3, 36, 3, 3, 2, 8, 1, 1, 7}, <<0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07>>},
    {:brainpoolP384r1, {1, 3, 36, 3, 3, 2, 8, 1, 1, 11}, <<0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b>>},
    {:brainpoolP512r1, {1, 3, 36, 3, 3, 2, 8, 1, 1, 13}, <<0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d>>},
    {:X25519, {1, 3, 101, 110}, <<0x06, 0x03, 0x2b, 0x65, 0x6e>>},
    {:Ed25519, {1, 3, 101, 112}, <<0x06, 0x03, 0x2b, 0x65, 0x70>>}
  ]

  test "parse ECParameters from ASN.1" do

    @curves
      |> Enum.each(fn {name, oid, der} ->
          assert {:ok, {:namedCurve, oid_found}} = :EC.decode(:ECParameters, der)
          assert oid_found == oid
      end)
  end

  test "encode ECParameters from named curve" do
    @curves
      |> Enum.each(fn {name, oid, der} ->
          assert {:ok, params} = P11ex.ECParam.ec_params_from_named_curve(name)
          assert params == der
      end)

    assert {:error, str} = P11ex.ECParam.ec_params_from_named_curve(:secp42r1)
    assert String.contains?(str, "secp42r1")
  end

end
