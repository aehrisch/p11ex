defmodule P11ex.ChunksTest do

  use ExUnit.Case, async: false

  alias P11ex.Session, as: Session

  setup_all do
    P11ex.TestHelper.setup_session()
  end

  @moduletag :chunks
  @moduletag :softhsm

  test "encrypt in chunks", context do

    key_id = :crypto.strong_rand_bytes(16)
    assert {:ok, key} =
      Session.generate_key(context.session_pid,
      {:ckm_aes_key_gen},
      [
        {:cka_token, false},
        {:cka_label, "test_key"},
        {:cka_value_len, 16},
        {:cka_id, key_id}
      ])

    iv = :crypto.strong_rand_bytes(12)
    params = %{iv: iv, tag_bits: 128}

    data_sizes = [5, 16, 32, 128, 256, 1024, 8192, 16_384]
    part_sizes = [3, 8, 16, 64, 100, 256]

    data_sizes
    |> Enum.each(fn data_size ->
        data = :crypto.strong_rand_bytes(data_size)

        # Split the data into chunks of the given size and encrypt each chunk
        part_sizes
        |> Enum.each(fn part_size ->
          chunks = for <<chunk::binary-size(part_size) <- data>>, do: chunk
          remainder = binary_part(data, div(byte_size(data), part_size) * part_size, rem(byte_size(data), part_size))
          chunks = if byte_size(remainder) > 0, do: chunks ++ [remainder], else: chunks

          :ok = Session.encrypt_init(context.session_pid, {:ckm_aes_gcm, params}, key)
          encrypted_chunks = for chunk <- chunks do
            {:ok, encrypted_chunk} = Session.encrypt_update(context.session_pid, chunk)
            encrypted_chunk
          end

          {:ok, final_encrypted} = Session.encrypt_final(context.session_pid)
          encrypted = Enum.join(encrypted_chunks) <> final_encrypted

          # Decrypt the result in a single step
          {:ok, decrypted} = Session.decrypt(context.session_pid, {:ckm_aes_gcm, params}, key, encrypted)

          assert data == decrypted
        end)
    end)
    :ok = Session.destroy_object(context.session_pid, key)
  end

  test "decrypt in chunks", context do

    key_id = :crypto.strong_rand_bytes(16)
    assert {:ok, key} =
      Session.generate_key(context.session_pid,
      {:ckm_aes_key_gen},
      [
        {:cka_token, false},
        {:cka_label, "test_key"},
        {:cka_value_len, 16},
        {:cka_id, key_id}
      ])

    data_sizes = [5, 16, 32, 128, 256, 1024, 8192, 16_384]
    part_sizes = [3, 8, 16, 64, 100, 256]

    iv = :crypto.strong_rand_bytes(12)
    params = %{iv: iv, tag_bits: 128}

    data_sizes
    |> Enum.each(fn data_size ->
        data = :crypto.strong_rand_bytes(data_size)

        # Encrypt the data in a single step
        {:ok, encrypted} = Session.encrypt(context.session_pid, {:ckm_aes_gcm, params}, key, data)

        # Split the ciphertext into chunks of the given size and decrypt each chunk
        part_sizes
        |> Enum.each(fn part_size ->
          chunks = for <<chunk::binary-size(part_size) <- encrypted>>, do: chunk
          remainder = binary_part(encrypted, div(byte_size(encrypted), part_size) * part_size, rem(byte_size(encrypted), part_size))
          chunks = if byte_size(remainder) > 0, do: chunks ++ [remainder], else: chunks

          :ok = Session.decrypt_init(context.session_pid, {:ckm_aes_gcm, params}, key)
          decrypted_chunks = for chunk <- chunks do
            {:ok, decrypted_chunk} = Session.decrypt_update(context.session_pid, chunk)
            decrypted_chunk
          end

          {:ok, final_decrypted} = Session.decrypt_final(context.session_pid)
          decrypted = Enum.join(decrypted_chunks) <> final_decrypted

          assert data == decrypted
        end)
    end)
    :ok = Session.destroy_object(context.session_pid, key)
  end

  test "digest in chunks", context do

    data_sizes = [5, 16, 32, 128, 256, 1024, 8192, 16_384]
    part_sizes = [3, 8, 16, 64, 100, 256]

    algs = [
      {:ckm_sha1, :sha},
      {:ckm_sha224, :sha224},
      {:ckm_sha256, :sha256},
      {:ckm_sha384, :sha384},
      {:ckm_sha512, :sha512}
    ]

    algs
      |> Enum.each(fn {digest_mech, digest_name} ->
        data_sizes
        |> Enum.each(fn data_size ->
          data = :crypto.strong_rand_bytes(data_size)

          part_sizes
          |> Enum.each(fn part_size ->
            chunks = for <<chunk::binary-size(part_size) <- data>>, do: chunk
            remainder = binary_part(data, div(byte_size(data), part_size) * part_size, rem(byte_size(data), part_size))
            chunks = if byte_size(remainder) > 0, do: chunks ++ [remainder], else: chunks

            :ok = Session.digest_init(context.session_pid, {digest_mech})

            for chunk <- chunks do
              :ok = Session.digest_update(context.session_pid, chunk)
            end

            {:ok, final_digest} = Session.digest_final(context.session_pid)
            assert :crypto.hash(digest_name, data) == final_digest
          end)
      end)
    end)
  end

  @moduletag :chunks_sign
  test "HMAC computation in chunks", context do

    data_sizes = [5, 16, 32, 128, 256, 1024, 8192, 16_384]
    part_sizes = [3, 8, 16, 64, 100, 256]

    {pubk, prvk} = P11exRSATestHelper.gen_keypair(context.session_pid)

    data_sizes
    |> Enum.each(fn data_size ->
      data = :crypto.strong_rand_bytes(data_size)

      part_sizes
      |> Enum.each(fn part_size ->
        chunks = for <<chunk::binary-size(part_size) <- data>>, do: chunk
        remainder = binary_part(data, div(byte_size(data), part_size) * part_size, rem(byte_size(data), part_size))
        chunks = if byte_size(remainder) > 0, do: chunks ++ [remainder], else: chunks

        :ok = Session.sign_init(context.session_pid, {:ckm_sha256_rsa_pkcs}, prvk)

        for chunk <- chunks do
          :ok = Session.sign_update(context.session_pid, chunk)
        end

        {:ok, signature} = Session.sign_final(context.session_pid)

        assert :ok = Session.verify_init(context.session_pid, {:ckm_sha256_rsa_pkcs}, pubk)
        assert :ok = Session.verify(context.session_pid, data, signature)
      end)
    end)

    :ok = Session.destroy_object(context.session_pid, pubk)
    :ok = Session.destroy_object(context.session_pid, prvk)
  end

end
