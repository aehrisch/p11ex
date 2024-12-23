defmodule P11ex.FlagsTest do
  use ExUnit.Case
  alias P11ex.Flags

  describe "slot flags" do
    test "converts flags to atoms" do
      assert Flags.to_atoms(:slot, 0x0003) == MapSet.new([:hw_slot, :removable_device])
      assert Flags.to_atoms(:slot, 0x0000) == MapSet.new([])
      assert Flags.to_atoms(:slot, 0x0007) == MapSet.new([:hw_slot, :removable_device, :token_present])
    end

    test "converts atoms to flags" do
      assert Flags.from_atoms(:slot, MapSet.new([:hw_slot, :removable_device])) == 0x0003
      assert Flags.from_atoms(:slot, MapSet.new([])) == 0x0000
      assert Flags.from_atoms(:slot, MapSet.new([:hw_slot, :removable_device, :token_present])) == 0x0007
    end
  end

  test "available_flags returns all flags for a type" do
    assert Flags.available_flags(:slot) == [:hw_slot, :removable_device, :token_present]
  end
end
