defmodule P11exCli.SignHelpers do

  defp exit, do: Application.fetch_env!(:p11ex_cli, :exit_mod)

  def parse_digest_mechanism!(nil), do: nil
  def parse_digest_mechanism!(mechanism_str) do
    case String.downcase(mechanism_str) do
      "none" -> nil
      "sha" -> :sha
      "sha224" -> :sha224
      "sha256" -> :sha256
      "sha384" -> :sha384
      "sha512" -> :sha512
      _ ->
        IO.puts(:stderr, "Invalid digest mechanism: #{mechanism_str}")
        exit().halt(:invalid_param)
    end
  end

  def parse_sign_mechanism!("ecdsa_plain", _), do: {:ckm_ecdsa}

  # RSA PKCS#1 v1.5 mechanisms, data will be hashed by P11exCli
  def parse_sign_mechanism!("rsa_pkcs", :sha), do: {:ckm_sha1_rsa_pkcs}
  def parse_sign_mechanism!("rsa_pkcs", :sha224), do: {:ckm_sha224_rsa_pkcs}
  def parse_sign_mechanism!("rsa_pkcs", :sha256), do: {:ckm_sha256_rsa_pkcs}
  def parse_sign_mechanism!("rsa_pkcs", :sha384), do: {:ckm_sha384_rsa_pkcs}
  def parse_sign_mechanism!("rsa_pkcs", :sha512), do: {:ckm_sha512_rsa_pkcs}
  def parse_sign_mechanism!("rsa_pkcs", _), do: {:ckm_rsa_pkcs}

  # RSA PKCS#1 v1.5 mechanisms, data was already hashed outside of P11exCli
  def parse_sign_mechanism!("rsa_pkcs_sha1", nil), do: {:ckm_sha1_rsa_pkcs}
  def parse_sign_mechanism!("rsa_pkcs_sha224", nil), do: {:ckm_sha224_rsa_pkcs}
  def parse_sign_mechanism!("rsa_pkcs_sha256", nil), do: {:ckm_sha256_rsa_pkcs}
  def parse_sign_mechanism!("rsa_pkcs_sha384", nil), do: {:ckm_sha384_rsa_pkcs}
  def parse_sign_mechanism!("rsa_pkcs_sha512", nil), do: {:ckm_sha512_rsa_pkcs}

  def parse_sign_mechanism!("rsa_pkcs_pss", digest) do
    case digest do
      :sha -> {:ckm_rsa_pkcs_pss, %{salt_len: 20, hash_alg: :sha, mgf_hash_alg: :sha}}
      :sha224 -> {:ckm_rsa_pkcs_pss, %{salt_len: 28, hash_alg: :sha224, mgf_hash_alg: :sha224}}
      :sha256 -> {:ckm_rsa_pkcs_pss, %{salt_len: 32, hash_alg: :sha256, mgf_hash_alg: :sha256}}
      :sha384 -> {:ckm_rsa_pkcs_pss, %{salt_len: 48, hash_alg: :sha384, mgf_hash_alg: :sha384}}
      :sha512 -> {:ckm_rsa_pkcs_pss, %{salt_len: 64, hash_alg: :sha512, mgf_hash_alg: :sha512}}
      _ ->
        IO.puts(:stderr, "Invalid or missing digest mechanism: #{digest}")
        exit().halt(:invalid_param)
    end
  end
  def parse_sign_mechanism!("rsa_pkcs_pss_sha", nil) do
    {:ckm_rsa_pkcs_pss, %{salt_len: 20, hash_alg: :sha, mgf_hash_alg: :sha}}
  end
  def parse_sign_mechanism!("rsa_pkcs_pss_sha224", nil) do
    {:ckm_rsa_pkcs_pss, %{salt_len: 28, hash_alg: :sha224, mgf_hash_alg: :sha224}}
  end
  def parse_sign_mechanism!("rsa_pkcs_pss_sha256", nil) do
    {:ckm_rsa_pkcs_pss, %{salt_len: 32, hash_alg: :sha256, mgf_hash_alg: :sha256}}
  end
  def parse_sign_mechanism!("rsa_pkcs_pss_sha384", nil) do
    {:ckm_rsa_pkcs_pss, %{salt_len: 48, hash_alg: :sha384, mgf_hash_alg: :sha384}}
  end
  def parse_sign_mechanism!("rsa_pkcs_pss_sha512", nil) do
    {:ckm_rsa_pkcs_pss, %{salt_len: 64, hash_alg: :sha512, mgf_hash_alg: :sha512}}
  end
  def parse_sign_mechanism!(mechanism, digest) do
    IO.puts(:stderr, "Invalid or missing sign mechanism: #{inspect(mechanism)} / #{inspect(digest)}")
    exit().halt(:invalid_param)
  end

  # True for CKM_SHA*_RSA_PKCS: token hashes the data and signs DigestInfo (no pre-hash in CLI).
  def mechanism_hashes_internally?({:ckm_sha1_rsa_pkcs}), do: true
  def mechanism_hashes_internally?({:ckm_sha224_rsa_pkcs}), do: true
  def mechanism_hashes_internally?({:ckm_sha256_rsa_pkcs}), do: true
  def mechanism_hashes_internally?({:ckm_sha384_rsa_pkcs}), do: true
  def mechanism_hashes_internally?({:ckm_sha512_rsa_pkcs}), do: true
  def mechanism_hashes_internally?(_), do: false

  def read_input_data!(file_path) do
    case File.read(file_path) do
      {:ok, data} -> data
      {:error, reason} ->
        IO.puts(:stderr, "Error reading input file: #{inspect(reason)}")
        exit().halt(:error)
    end
  end

  # Parse output format string
  def parse_format!(format_str) do
    case String.downcase(format_str) do
      "bin" -> :bin
      "hex" -> :hex
      "base64" -> :base64
      _ ->
        IO.puts(:stderr, "Invalid output format: #{format_str}. Must be bin, hex, or base64")
        exit().halt(:invalid_param)
    end
  end

  def format_signature(signature, mechanism, :bin), do: encode_signature(mechanism, signature)
  def format_signature(signature, mechanism, :hex), do: Base.encode16(encode_signature(mechanism, signature), case: :lower)
  def format_signature(signature, mechanism, :base64), do: Base.encode64(encode_signature(mechanism, signature))

  def encode_signature({:ckm_ecdsa}, signature) do
    {:ok, asn1_sig} = P11ex.ECSignature.recode_as_asn1(signature)
    asn1_sig
  end
  def encode_signature(_, signature), do: signature


  # Write output (file or stdout)
  def write_output(file_path, data) do
    case File.write(file_path, data) do
      :ok ->
        IO.puts("Signature written to: #{file_path}")
      {:error, reason} ->
        IO.puts(:stderr, "Error writing output file: #{inspect(reason)}")
        exit().halt(:error)
    end
  end

end
