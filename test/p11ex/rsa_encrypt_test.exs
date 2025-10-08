defmodule P11ex.RsaEncryptTest do

  use ExUnit.Case, async: false

  alias P11ex.Session, as: Session

  @moduletag :rsa
  @moduletag :rsa_encrypt
  @moduletag :softhsm

  setup_all do
    P11ex.TestHelper.setup_session()
  end

  # test "encrypt/decrypt with RSA PKCS#1 v1.5", %{session_pid: session_pid} = context do

  #   {pubk, prvk} = P11exRSATestHelper.gen_keypair(session_pid)

  #   data = :crypto.strong_rand_bytes(128)
  #   mechanism = {:ckm_rsa_pkcs}

  #   {:ok, ciphertext} = Session.encrypt(session_pid, mechanism, pubk, data)
  #   assert data != ciphertext

  #   {:ok, plaintext} = Session.decrypt(session_pid, mechanism, prvk, ciphertext)
  #   assert plaintext == data

  #   Session.destroy_object(context.session_pid, pubk)
  #   Session.destroy_object(context.session_pid, prvk)
  # end

  test "encrypt/decrypt with RSA OAEP", %{session_pid: session_pid} = context do

    {pubk, prvk} = RSATestHelper.gen_keypair(session_pid)

    plain_data = :crypto.strong_rand_bytes(128)
    source_data = :crypto.strong_rand_bytes(16)

    parameters = [
      %{hash_alg: :sha, mgf_hash_alg: :sha},
      #%{hash_alg: :sha224, mgf_hash_alg: :sha224},
      #%{hash_alg: :sha256, mgf_hash_alg: :sha256},
      #%{hash_alg: :sha384, mgf_hash_alg: :sha384},
      #%{hash_alg: :sha512, mgf_hash_alg: :sha512},
      #%{hash_alg: :sha, mgf_hash_alg: :sha, source_data: source_data},
      #%{hash_alg: :sha224, mgf_hash_alg: :sha224, source_data: source_data},
      #%{hash_alg: :sha256, mgf_hash_alg: :sha256, source_data: source_data},
      #%{hash_alg: :sha384, mgf_hash_alg: :sha384, source_data: source_data},
      #%{hash_alg: :sha512, mgf_hash_alg: :sha512, source_data: source_data}
    ]

    parameters
    |> Enum.each(fn parameters ->
      mechanism = {:ckm_rsa_pkcs_oaep, parameters}

      {:ok, ciphertext} = Session.encrypt(session_pid, mechanism, pubk, plain_data)
      assert plain_data != ciphertext

      {:ok, plaintext} = Session.decrypt(session_pid, mechanism, prvk, ciphertext)
      assert plaintext == plain_data
    end)
  end

  test "RSA OAEP with invalid hash parameters", %{session_pid: session_pid} = context do

    {pubk, prvk} = RSATestHelper.gen_keypair(session_pid)
    plain_data = :crypto.strong_rand_bytes(128)

    [
      %{hash_alg: :sha100, mgf_hash_alg: :sha224},
      %{hash_alg: "sha256", mgf_hash_alg: :sha224}
    ] |> Enum.each(fn parameters ->
      mechanism = {:ckm_rsa_pkcs_oaep, parameters}
      assert {:error, :invalid_hash_alg_parameter, _} = Session.encrypt(session_pid, mechanism, pubk, plain_data)
    end)

    Session.destroy_object(session_pid, pubk)
    Session.destroy_object(session_pid, prvk)
  end

  test "RSA OAEP with invalid mgf hash parameters", %{session_pid: session_pid} = context do

    {pubk, prvk} = RSATestHelper.gen_keypair(session_pid)
    plain_data = :crypto.strong_rand_bytes(128)

    [
      %{hash_alg: :sha, mgf_hash_alg: :sha100},
      %{hash_alg: :sha, mgf_hash_alg: "sha"}
    ] |> Enum.each(fn parameters ->
      mechanism = {:ckm_rsa_pkcs_oaep, parameters}
      assert {:error, :invalid_mgf_hash_alg_parameter, _} = Session.encrypt(session_pid, mechanism, pubk, plain_data)
    end)

    Session.destroy_object(session_pid, pubk)
    Session.destroy_object(session_pid, prvk)
  end

  test "RSA OAEP with missing parameters", %{session_pid: session_pid} = context do

    {pubk, prvk} = RSATestHelper.gen_keypair(session_pid)
    plain_data = :crypto.strong_rand_bytes(128)

    mechanism = {:ckm_rsa_pkcs_oaep, %{}}
    assert {:error, :invalid_hash_alg_parameter, _} = Session.encrypt(session_pid, mechanism, pubk, plain_data)

  end

end
