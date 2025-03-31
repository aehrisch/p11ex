defmodule P11ex.YubikeyTest do

  use ExUnit.Case, async: false

  alias P11ex.Lib, as: Lib
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

    assert MapSet.member?(MapSet.new(token_info.flags), :login_required)
    assert MapSet.member?(MapSet.new(token_info.flags), :rng)
    assert MapSet.member?(MapSet.new(token_info.flags), :token_initialized)
    assert MapSet.member?(MapSet.new(token_info.flags), :user_pin_initialized)
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
  end
end
