defmodule P11ex.MechanismInfoTest do
  use ExUnit.Case

  @moduletag :softhsm

  @moduledoc """
  Basic tests for `P11ex.Module.list_mechanisms/2` and
  `P11ex.Module.mechanism_info/3`. The test requires
  SoftHSM 2.6.1.
  """

  alias P11ex.Module, as: Module

  setup_all do
    {:ok, %{slot: slot}} = P11ex.TestHelper.find_slot()
    {:ok, %{slot: slot}}
  end

  # Get list of mechanisms and do some basic checks
  # on the values.
  @tag :mechanism_info
  test "list mechanisms", context do

    {:ok, mechanisms} = P11ex.Module.list_mechanisms(context.slot)

    assert is_list(mechanisms)
    assert length(mechanisms) > 0

    assert Enum.all?(mechanisms, fn m ->
      assert is_integer(m) || is_atom(m)
    end)

    assert Enum.member?(mechanisms, :ckm_aes_cbc)
    assert Enum.member?(mechanisms, :ckm_aes_gcm)
  end

  @tag :mechanism_info
  test "get mechanism info", context do

    # two different ways to specify the same mechanism
    [0x00001082, :ckm_aes_cbc]
      |> Enum.each(fn m ->
          {:ok, info} = P11ex.Module.mechanism_info(context.slot, m)

          assert is_map(info)
          assert Map.has_key?(info, :flags)
          assert info.flags == MapSet.new([:wrap, :encrypt, :decrypt])
          assert info.min_length == 16
          assert info.max_length == 32
      end)
  end

  @tag :mechanism_info
  test "get mechanism info for unknown mechanism", context do

    {:error, {:C_GetMechanismInfo, :ckr_mechanism_invalid}} =
      P11ex.Module.mechanism_info(context.slot, 0x039399)
  end

end
