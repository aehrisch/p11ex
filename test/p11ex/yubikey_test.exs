defmodule P11ex.YubikeyTest do

  use ExUnit.Case, async: false

  alias P11ex.Module, as: Module
  alias P11ex.Session, as: Session

  @moduletag :yubikey

  @moduledoc """
  This module runs some integration tests against a YubiKey PIV token.
  """

  test "YubiKey, list slots" do

    {:ok, slots} = Module.list_slots(true)

    assert is_list(slots)
    assert length(slots) == 1

    slot = List.first(slots)
    assert slot.slot_id == 0
    assert Regex.match?(~r/^Yubico YubiKey/, slot.description)
    assert Regex.match?(~r/^Yubico/, slot.manufacturer_id)
    assert slot.hardware_version == {1, 0}
    assert slot.firmware_version == {1, 0}
    assert MapSet.new(slot.flags) == MapSet.new([:hw_slot, :removable_device, :token_present])
  end

  test "YubiKey, token info" do

    {:ok, [slot]} = Module.list_slots(true)
    {:ok, token_info} = Module.token_info(slot)

    assert Regex.match?(~r/^YubiKey PIV/, token_info.label)
    assert Regex.match?(~r/^Yubico/, token_info.manufacturer_id)
    assert Regex.match?(~r/^YubiKey/, token_info.model)

    assert token_info.flags != nil
    assert is_map(token_info.flags)
    assert MapSet.member?(token_info.flags, :login_required)
    assert MapSet.member?(token_info.flags, :rng)
    assert MapSet.member?(token_info.flags, :token_initialized)
    assert MapSet.member?(token_info.flags, :user_pin_initialized)

    assert is_binary(token_info.serial_number)
    assert is_tuple(token_info.firmware_version)
    assert token_info.hardware_version == {1, 0}

    assert token_info.max_session_count > 0
    assert token_info.max_rw_session_count > 0
    assert token_info.session_count >= 0
    assert token_info.rw_session_count >= 0

    assert token_info.min_pin_len >= 6
    assert token_info.max_pin_len >= 32

    assert token_info.utc_time == nil

    IO.inspect(token_info, label: "token_info")
  end

  test "YubiKey, compute digest" do

    {:ok, [slot]} = Module.list_slots(true)
    {:ok, session_pid} = Session.start_link([
      module: Module,
      slot_id: slot.slot_id,
      flags: [:rw_session, :serial_session]
    ])

    {:ok, random} = Session.generate_random(session_pid, 16)
    assert is_binary(random)
    assert byte_size(random) == 16

    algs = [
      {:ckm_sha1, 20, :sha},
      {:ckm_sha256, 32, :sha256},
      {:ckm_sha384, 48, :sha384},
      {:ckm_sha512, 64, :sha512}
    ]

    algs |> Enum.each(fn {mechanism, size, name} ->
      :ok = Session.digest_init(session_pid, {mechanism})
      {:ok, digest} = Session.digest(session_pid, random)

      assert digest != nil
      assert is_binary(digest)
      assert byte_size(digest) == size
      assert :crypto.hash(name, random) == digest
    end)
  end
end
