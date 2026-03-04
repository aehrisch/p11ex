defmodule P11ex.ECSignature do

  @spec recode_as_asn1(binary) :: {:ok, binary} | {:error, String.t}
  def recode_as_asn1(r_and_s_bytes) when is_binary(r_and_s_bytes) do
    sig_size = byte_size(r_and_s_bytes)
    case rem(sig_size, 2) do
      0 ->
        half_size = div(sig_size, 2)
        <<r::binary-size(half_size), s::binary>> = r_and_s_bytes
        sig_value = %{
          r: :binary.decode_unsigned(r),
          s: :binary.decode_unsigned(s)
        }
        :EC.encode(:ECSignature, sig_value)
      _ ->
        {:error, "Invalid signature size: #{sig_size}"}
    end
  end

end
