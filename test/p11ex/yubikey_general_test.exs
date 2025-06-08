defmodule P11ex.YubikeyGeneralTest do
  use ExUnit.Case, async: false

  alias P11ex.Module, as: Module

  @moduletag :general
  @moduletag :yubikey

  setup_all do
    {:ok, context} = YubikeyTestHelper.setup_session()
    {:ok, context}
  end

  test "YubiKey token info" do

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
  end

end
