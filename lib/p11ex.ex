defmodule P11ex do

  defmodule Module do
    @enforce_keys [:path, :p11_module]
    defstruct path: nil, p11_module: nil
  end

  defmodule Slot do
    defstruct [:module, :slot_id, :description, :manufacturer_id, :hardware_version, :firmware_version, :flags]
  end

  @on_load :load_nifs

  def load_nifs do
    # Path to the compiled NIF library
    path = :filename.join(:code.priv_dir(:p11ex), "p11ex_nif")
    :erlang.load_nif(path, 0)
  end

  @spec load_module(String.t()) :: {:ok, Module.t()} | {:error, String.t()}
  def load_module(path) do
    with {:ok, p11_module} <- n_load_module(String.to_charlist(path)) do
      {:ok, %Module{path: path, p11_module: p11_module}}
    end
  end

  def list_slots(module, token_present) do
    with {:ok, slots} <- n_list_slots(module.p11_module, token_present) do
      {:ok, Enum.map(slots, fn slot -> interpret_slot(module, slot) end)}
    end
  end


  def token_info(module, slot_id) do
    with {:ok, token_info} <- n_token_info(module.p11_module, slot_id) do
      {:ok, trim_map_strings(token_info)}
    end
  end

  defp interpret_slot(module, n_slot) do
    with {slot_id, desc, manufacturer_id, hardware_version, firmware_version, flags} <- n_slot do
      %Slot{
        module: module,
        slot_id: slot_id,
        description: String.trim_trailing(desc),
        manufacturer_id: String.trim_trailing(manufacturer_id),
        hardware_version: hardware_version,
        firmware_version: firmware_version,
        flags: P11ex.Flags.to_atoms(:slot, flags) |> MapSet.to_list()
      }
    end
  end

  defp n_load_module(_path) do
    # This function will be implemented in NIF
    raise "NIF load_module/1 not implemented"
  end

  defp n_list_slots(_p11_module, _token_present) do
    # This function will be implemented in NIF
    raise "NIF list_slots/1 not implemented"
  end

  defp n_token_info(_p11_module, _slot_id) do
    # This function will be implemented in NIF
    raise "NIF token_info/1 not implemented"
  end

  defp trim_map_strings(map) when is_map(map) do
    map
    |> Map.new(fn {k, v} ->
      {k, trim_value(v)}
    end)
    |> Map.update(:flags, 0, fn (v) -> P11ex.Flags.to_atoms(:token, v) |> MapSet.to_list() end)
  end

  defp trim_value(value) when is_binary(value), do: String.trim(value)
  defp trim_value(value), do: value

end
