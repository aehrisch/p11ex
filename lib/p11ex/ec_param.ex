defmodule P11ex.ECParam do

  @named_curves [
    {:secp192r1, {1,2,840,10045,3,1,1}},
    {:secp224r1, {1,3,132,0,33}},
    {:secp256r1, {1,2,840,10045,3,1,7}},
    {:secp384r1, {1,3,132,0,34}},
    {:secp521r1, {1,3,132,0,35}},
    {:brainpoolP256r1, {1,3,36,3,3,2,8,1,1,7}},
    {:brainpoolP384r1, {1,3,36,3,3,2,8,1,1,11}},
    {:brainpoolP512r1, {1,3,36,3,3,2,8,1,1,13}},
    {:X25519, {1,3,101,110}},
    {:Ed25519, {1,3,101,112}}
  ]

  @doc """
  List of named curves supported by the library.
  """
  @spec named_curves() :: list(atom())
  def named_curves do
    Enum.map(@named_curves, fn {name, _} -> name end)
  end

  @doc """
  Encode ECParameters for a named curve. ECParameters is a
  DER-encoded ASN.1 structure that identifies a named curve and
  can be used as a value for the `cka_ec_params` attribute of
  a key template.

  ## Examples

      iex> P11ex.ECParam.ec_params_from_named_curve(:secp256r1)
      {:ok, <<0x06, ...}

      iex> P11ex.ECParam.ec_params_from_named_curve(:secp42r1)
      {:error, "Unknown named curve: secp42r1"}

  """
  @spec ec_params_from_named_curve(atom) :: {:ok, binary} | {:error, String.t}
  def ec_params_from_named_curve(name) do
    case Enum.find(@named_curves, fn {n, _oid} -> n == name end) do
      nil -> {:error, "Unknown named curve: #{name}"}
      {_, oid} -> :EC.encode(:ECParameters, {:namedCurve, oid})
    end
  end

end
