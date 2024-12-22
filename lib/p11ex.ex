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
    case :erlang.load_nif(path, 0) do
      :ok -> :ok
      {:error, reason} ->
        IO.puts "Failed to load NIF: #{reason}"
        :error
    end
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

  defp interpret_slot(module, n_slot) do
    with {slot_id, desc, manufacturer_id, hardware_version, firmware_version, flags} <- n_slot do
      %Slot{
        module: module,
        slot_id: slot_id,
        description: String.trim_trailing(desc),
        manufacturer_id: String.trim_trailing(manufacturer_id),
        hardware_version: hardware_version,
        firmware_version: firmware_version,
        flags: flags
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
end
