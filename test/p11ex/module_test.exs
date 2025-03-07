defmodule P11ex.ModuleTest do
  use ExUnit.Case

  @moduledoc """
  Basic tests for `P11ex.Module`: Lists lots and finds slots by label.
  These operations do not require a login.
  """

  alias P11ex.Module, as: Module

  test "list_slots" do
    {:ok, slots} = Module.list_slots(true)
    assert is_list(slots)
    assert Enum.count(slots) == 2

    {:ok, slots} = Module.list_slots(false)
    assert is_list(slots)
    assert Enum.count(slots) == 2
  end

  test "find_slot_by_tokenlabel" do
    token_label = Application.fetch_env!(:p11ex, :token_label)
    {:ok, slot} = Module.find_slot_by_tokenlabel(token_label)
    assert is_map(slot)
    assert slot.manufacturer_id == "SoftHSM project"
    assert {2, minor} = slot.firmware_version
    assert minor >= 6
    assert {2, minor} = slot.hardware_version
    assert minor >= 6

    assert {:ok, nil} = Module.find_slot_by_tokenlabel("Does not exist")
  end

  test "token_info" do
    token_label = Application.fetch_env!(:p11ex, :token_label)
    {:ok, slot} = Module.find_slot_by_tokenlabel(token_label)
    assert is_map(slot)

    {:ok, token_info} = Module.token_info(slot)
    assert is_map(token_info)
    assert token_info.label == token_label
    assert token_info.manufacturer_id == "SoftHSM project"
    assert token_info.model == "SoftHSM v2"
    {2, minor} = token_info.firmware_version
    assert minor >= 6
  end
end
