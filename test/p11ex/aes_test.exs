defmodule P11ExTest.AesKeygen do

  use ExUnit.Case, async: false

  alias P11ex.Lib, as: Lib
  alias P11ex.Session, as: Session

  setup_all do
    P11ex.TestHelper.setup_session()
  end

  @moduletag :aes
  @moduletag :softhsm

  # This test generates an AES key and computes the key check value (KCV). The KCV
  # computed must match the key check value stored in the attribute (cka_check_value).
  test "aes key generation, compute KCV", context do

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

    assert %Lib.ObjectHandle{} = key
    assert is_integer(key.handle) and key.handle > 0

    {:ok, [object | []]} = Session.find_objects(context.session_pid, [{:cka_id, key_id}], 5)
    {:ok, attribs, []} = Session.read_object(context.session_pid, object, :cko_secret_key)

    null_block = <<0::size(128)>>
    {:ok, encrypted} = Session.encrypt(context.session_pid, {:ckm_aes_ecb}, object, null_block)
    assert is_binary(encrypted)
    assert byte_size(encrypted) == 16

    # The key check value is the first three bytes of the AES ECB
    # encrypted null block.
    assert :binary.part(encrypted, 0, 3) == attribs.cka_check_value

    assert :ok == Session.destroy_object(context.session_pid, key)
  end

  # This test generates an AES key and sets some attributes to non-default values.
  # It then reads the attributes and verifies that they are set correctly.
  test "aes key generation, special attributes", context do

    key_id = :crypto.strong_rand_bytes(16)
    assert {:ok, key} =
      Session.generate_key(context.session_pid,
      {:ckm_aes_key_gen},
      [
        {:cka_token, false},
        {:cka_label, "test_key"},
        {:cka_value_len, 16},
        {:cka_id, key_id},
        {:cka_encrypt, true},
        {:cka_decrypt, false},
        {:cka_derive, false},
        {:cka_sign, false}
      ])

    {:ok, attribs, []} = Session.read_object(context.session_pid, key, :cko_secret_key)
    assert attribs.cka_id == key_id
    assert attribs.cka_label == "test_key"
    assert attribs.cka_value_len == 16
    assert attribs.cka_encrypt == true
    assert attribs.cka_decrypt == false
    assert attribs.cka_derive == false
    assert attribs.cka_sign == false

    assert :ok == Session.destroy_object(context.session_pid, key)
  end

  # This test encrypts with AES ECB using a single call to encrypt
  test "aes_ebc encrypt/decrypt, one call", context do

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

    [16, 32, 128, 256, 1024, 8192, 16_384]
    |> Enum.each(fn size ->
      data = :crypto.strong_rand_bytes(size)
      assert {:ok, encrypted} = Session.encrypt(context.session_pid, {:ckm_aes_ecb}, key, data)
      assert byte_size(encrypted) == size
      assert {:ok, decrypted} = Session.decrypt(context.session_pid, {:ckm_aes_ecb}, key, encrypted)
      assert data == decrypted
    end)
  end


  test "aes_cbc encrypt/decrypt, one call", context do

    iv = :crypto.strong_rand_bytes(16)
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

      # The CBC mode requires the input data to be a multiple
      #of the block size as it does not perform padding.
      data_size = [16, 32, 256, 1024, 8192]

      data_size
      |> Enum.each(fn data_size ->
        data = :crypto.strong_rand_bytes(data_size)

        assert {:ok, encrypted} = Session.encrypt(context.session_pid, {:ckm_aes_cbc, %{iv: iv}}, key, data)

        assert {:ok, decrypted} = Session.decrypt(context.session_pid, {:ckm_aes_cbc, %{iv: iv}}, key, encrypted)
        assert data == decrypted
      end)

      :ok = Session.destroy_object(context.session_pid, key)
  end

  test "aes_cbc/aes_ofb encrypt, wrong IV", context do

    iv_wrong_size = :crypto.strong_rand_bytes(12)

    key_id = :crypto.strong_rand_bytes(17)
    assert {:ok, key} =
      Session.generate_key(context.session_pid,
      {:ckm_aes_key_gen},
      [
        {:cka_token, false},
        {:cka_label, "test_key"},
        {:cka_value_len, 16},
        {:cka_id, key_id}
      ])

    data = :crypto.strong_rand_bytes(64)

    [:ckm_aes_cbc, :ckm_aes_ofb]
      |> Enum.each(fn mech ->
        # Missing the IV parameter.
        assert {:error, {:C_EncryptInit, :ckr_arguments_bad}} =
          Session.encrypt(context.session_pid, {:ckm_aes_cbc}, key, data)

        # The IV must be the same size as the block size.
        assert {:error, :invalid_iv_parameter, _ignore} =
          Session.encrypt(context.session_pid, {:ckm_aes_cbc, %{iv: iv_wrong_size}}, key, data)

        # Missing the iv parameter.
        assert {:error, :invalid_iv_parameter} =
          Session.encrypt(context.session_pid, {:ckm_aes_cbc, %{}}, key, data)

        # Wrong type for the iv parameter.
        assert {:error, :invalid_iv_parameter} =
          Session.encrypt(context.session_pid, {:ckm_aes_cbc, %{iv: 42}}, key, data)
      end)

    :ok = Session.destroy_object(context.session_pid, key)
  end

  test "aes_ctr encrypt/decrypt, one call", context do

    iv = :crypto.strong_rand_bytes(16)
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

      counter_bits = [32, 64, 128]

      # The CBC mode requires the input data to be a multiple
      #of the block size as it does not perform padding.
      data_size = [16, 32, 256, 1024, 8192]

      data_size
      |> Enum.each(fn data_size ->
        counter_bits
        |> Enum.each(fn counter_bits ->
          params = %{iv: iv, counter_bits: counter_bits}

          data = :crypto.strong_rand_bytes(data_size)

          assert {:ok, encrypted} = Session.encrypt(context.session_pid, {:ckm_aes_ctr, params}, key, data)

          assert {:ok, decrypted} = Session.decrypt(context.session_pid, {:ckm_aes_ctr, params}, key, encrypted)
          assert data == decrypted
        end)
      end)

      :ok = Session.destroy_object(context.session_pid, key)
  end

  test "aes_ctr encrypt/decrypt, wrong IV", context do

    iv_wrong_size = :crypto.strong_rand_bytes(12)
    iv_valid = :crypto.strong_rand_bytes(16)

    key_id = :crypto.strong_rand_bytes(17)
    assert {:ok, key} =
      Session.generate_key(context.session_pid,
      {:ckm_aes_key_gen},
      [
        {:cka_token, false},
        {:cka_label, "test_key"},
        {:cka_value_len, 16},
        {:cka_id, key_id}
      ])

    data = :crypto.strong_rand_bytes(64)

    # The IV must be the same size as the block size.
    assert {:error, :invalid_iv_parameter, _ignore} =
      Session.encrypt(context.session_pid,
        {:ckm_aes_ctr, %{iv: iv_wrong_size, counter_bits: 16}},
        key, data)

    # The IV is missing.
    assert {:error, :invalid_iv_parameter, _ignore} =
      Session.encrypt(context.session_pid,
        {:ckm_aes_ctr, %{counter_bits: 16}},
        key, data)

    # The IV is of the wrong type.
    assert {:error, :invalid_iv_parameter, _ignore} =
      Session.encrypt(context.session_pid,
        {:ckm_aes_ctr, %{iv: 23, counter_bits: 16}},
        key, data)

    # The counter_bits parameter is missing.
    assert {:error, :invalid_counter_bits_parameter, _ignore} =
      Session.encrypt(context.session_pid,
        {:ckm_aes_ctr, %{iv: iv_valid}},
        key, data)

    # The counter_bits parameter is of the wrong type.
    assert {:error, :invalid_counter_bits_parameter, _ignore} =
      Session.encrypt(context.session_pid,
        {:ckm_aes_ctr, %{iv: iv_valid, counter_bits: <<1, 2, 3>>}},
        key, data)

    # The counter_bits parameter is negative
    assert {:error, :invalid_counter_bits_parameter, _ignore} =
      Session.encrypt(context.session_pid,
        {:ckm_aes_ctr, %{iv: iv_valid, counter_bits: -8}},
        key, data)

    # The counter_bits parameter is not a multiple of 8.
    assert {:error, :invalid_counter_bits_parameter, _ignore} =
      Session.encrypt(context.session_pid,
        {:ckm_aes_ctr, %{iv: iv_valid, counter_bits: 17}},
        key, data)

    # The counter_bits parameter is larger than 128.
    assert {:error, :invalid_counter_bits_parameter, _ignore} =
      Session.encrypt(context.session_pid,
        {:ckm_aes_ctr, %{iv: iv_valid, counter_bits: 144}},
        key, data)

    :ok = Session.destroy_object(context.session_pid, key)
  end

  @tag :aes_gcm
  test "aes_gcm encrypt/decrypt, one call", context do
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

    # Use a 12-byte IV which is standard for AES-GCM
    iv = :crypto.strong_rand_bytes(12)

    data_size = [5, 16, 32, 64, 128]
    aad = [0, 8, 16, 50, 128]
      |> Enum.map(fn aad_size -> :crypto.strong_rand_bytes(aad_size) end)

    aad ++ [:not_set]
    |> Enum.each(fn aad ->
      data_size
      |> Enum.each(fn data_size ->
        data = :crypto.strong_rand_bytes(data_size)
        params = if aad == :not_set do
          %{iv: iv, tag_bits: 128}
        else
         %{iv: iv, aad: aad, tag_bits: 128}
       end

        # Then encrypt the data
        assert {:ok, encrypted} = Session.encrypt(context.session_pid, {:ckm_aes_gcm, params}, key, data)

        # Verify the encrypted data is not empty and has the expected size
        assert is_binary(encrypted)
        assert byte_size(encrypted) > 0

        # Try to decrypt
        assert {:ok, decrypted} = Session.decrypt(context.session_pid, {:ckm_aes_gcm, params}, key, encrypted)
        assert data == decrypted
      end)
    end)

    :ok = Session.destroy_object(context.session_pid, key)
  end

end
