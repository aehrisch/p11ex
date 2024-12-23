defmodule P11ex.Flags do
  import Bitwise, only: [&&&: 2, |||: 2]

  @moduledoc """
  Handles conversion between PKCS#11 flags (CK_FLAGS) and MapSets of atoms.
  """

  @type flag_value :: non_neg_integer()
  @type flag_name :: atom()
  @type flag_type :: :slot | :token | :mechanism

  @slot_flags %{
    hw_slot: 0x0001,
    removable_device: 0x0002,
    token_present: 0x0004
  }

  @token_flags %{
    rng: 0x00000001,
    write_protected: 0x00000002,
    login_required: 0x00000004,
    user_pin_initialized: 0x00000008,
    restore_key_not_needed: 0x00000020,
    clock_on_token: 0x00000040,
    protected_authentication_path: 0x00000100,
    dual_crypto_operations: 0x00000200,
    token_initialized: 0x00000400,
    secondary_authentication: 0x00000800,
    user_pin_count_low: 0x00010000,
    user_pin_final_try: 0x00020000,
    user_pin_locked: 0x00040000,
    user_pin_to_be_changed: 0x00080000,
    so_pin_count_low: 0x00100000,
    so_pin_final_try: 0x00200000,
    so_pin_locked: 0x00400000,
    so_pin_to_be_changed: 0x00800000,
    error_state: 0x01000000
  }

  @mechanism_flags %{
    hw: 0x00000001,
    encrypt: 0x00000100,
    decrypt: 0x00000200,
    digest: 0x00000400,
    sign: 0x00000800,
    sign_recover: 0x00001000,
    verify: 0x00002000,
    verify_recover: 0x00004000,
    generate: 0x00008000,
    generate_key_pair: 0x00010000,
    wrap: 0x00020000,
    unwrap: 0x00040000,
    derive: 0x00080000,
    extension: 0x80000000
  }

  @flag_types %{
    slot: @slot_flags,
    token: @token_flags,
    mechanism: @mechanism_flags
  }

  @doc """
  Converts a flags integer to a MapSet of atoms for the given flag type.

  ## Examples

      iex> P11ex.Flags.to_atoms(:slot, 0x0003)
      #MapSet<[:hw_slot, :removable_device]>
  """
  @spec to_atoms(flag_type(), flag_value()) :: MapSet.t(flag_name())
  def to_atoms(type, flags) when is_integer(flags) and flags >= 0 do
    flag_map = Map.fetch!(@flag_types, type)

    flag_map
    |> Enum.filter(fn {_name, value} -> (flags &&& value) != 0 end)
    |> Enum.map(fn {name, _value} -> name end)
    |> MapSet.new()
  end

  @doc """
  Converts a MapSet of atoms to a flags integer for the given flag type.

  ## Examples

      iex> P11ex.Flags.from_atoms(:slot, MapSet.new([:hw_slot, :removable_device]))
      0x0003
  """
  @spec from_atoms(flag_type(), MapSet.t(flag_name())) :: flag_value()
  def from_atoms(type, flag_set) do
    flag_map = Map.fetch!(@flag_types, type)

    Enum.reduce(flag_set, 0, fn flag_name, acc ->
      case Map.fetch(flag_map, flag_name) do
        {:ok, value} -> acc ||| value
        :error -> acc
      end
    end)
  end

  @doc """
  Returns all possible flags for the given type.

  ## Examples

      iex> P11ex.Flags.available_flags(:slot)
      [:hw_slot, :removable_device, :token_present]
  """
  @spec available_flags(flag_type()) :: [flag_name()]
  def available_flags(type) do
    @flag_types
    |> Map.fetch!(type)
    |> Map.keys()
    |> Enum.sort()
  end
end
