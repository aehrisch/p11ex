defmodule P11ExTest.MacTest do

  use ExUnit.Case, async: false

  alias P11ex.Session, as: Session

  @moduletag :mac

  setup_all do
    P11ex.TestHelper.setup_session()
  end

  test "AES/CMAC, one call", context do

    key_id = :crypto.strong_rand_bytes(16)

    assert {:ok, _key} =
      Session.generate_key(context.session_pid,
      {:ckm_aes_key_gen},
      [
        {:cka_token, false},
        {:cka_label, "cmac_key"},
        {:cka_value_len, 32},
        {:cka_id, key_id}
      ])

      {:ok, [object | []]} =
        Session.find_objects(context.session_pid, [{:cka_id, key_id}], 5)

      # This algoirthm has no parameters
      :ok = Session.sign_init(context.session_pid, {:ckm_aes_cmac}, object)

      test_data = :crypto.strong_rand_bytes(64)
      {:ok, mac} = Session.sign(context.session_pid, test_data)
      assert mac != nil
      assert is_binary(mac)
      assert byte_size(mac) == 16

      :ok = Session.destroy_object(context.session_pid, object)
  end

  test "AES/CMAC, multiple calls", context do

    key_id = :crypto.strong_rand_bytes(16)

    assert {:ok, _key} =
      Session.generate_key(context.session_pid,
      {:ckm_aes_key_gen},
      [
        {:cka_token, false},
        {:cka_label, "cmac_key"},
        {:cka_value_len, 32},
        {:cka_id, key_id}
      ])

      {:ok, [object | []]} =
        Session.find_objects(context.session_pid, [{:cka_id, key_id}], 5)

      data_sizes = [16, 32, 100, 256, 1025, 8192, 16_384]
      part_sizes = [8, 16, 64, 100, 256]

      data_sizes
      |> Enum.each(fn data_size ->
        data = :crypto.strong_rand_bytes(data_size)

        part_sizes
        |> Enum.each(fn part_size ->
          chunks = for <<chunk::binary-size(part_size) <- data>>, do: chunk
          remainder = binary_part(data, div(byte_size(data), part_size) * part_size, rem(byte_size(data), part_size))
          chunks = if byte_size(remainder) > 0, do: chunks ++ [remainder], else: chunks

          :ok = Session.sign_init(context.session_pid, {:ckm_aes_cmac}, object)
          for chunk <- chunks do
            :ok = Session.sign_update(context.session_pid, chunk)
          end

          {:ok, mac} = Session.sign_final(context.session_pid)
          assert mac != nil
          assert is_binary(mac)
          assert byte_size(mac) == 16
        end)
      end)

      :ok = Session.destroy_object(context.session_pid, object)
  end

  test "AES SHA HMAC algorithms, one call", context do

    key_id = :crypto.strong_rand_bytes(16)

    assert {:ok, _key} =
      Session.generate_key(context.session_pid,
      {:ckm_generic_secret_key_gen},
      [
        {:cka_token, false},
        {:cka_label, "hmac_key"},
        {:cka_value_len, 128},
        {:cka_id, key_id}
      ])

    algs = [
      {:ckm_sha1_hmac, 160/8},
      {:ckm_sha224_hmac, 224/8},
      {:ckm_sha256_hmac, 256/8},
      {:ckm_sha384_hmac, 384/8},
      {:ckm_sha512_hmac, 512/8}
    ]

    {:ok, [object | []]} =
      Session.find_objects(context.session_pid, [{:cka_id, key_id}], 5)

    test_data = :crypto.strong_rand_bytes(512)
    for {alg, output_len} <- algs do
      :ok = Session.sign_init(context.session_pid, {alg}, object)
      {:ok, mac} = Session.sign(context.session_pid, test_data)
      assert mac != nil
      assert is_binary(mac)
      assert byte_size(mac) == output_len
    end

    :ok = Session.destroy_object(context.session_pid, object)
  end

end
