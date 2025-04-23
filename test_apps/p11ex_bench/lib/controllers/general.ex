defmodule P11exBench.Controllers.General do
  alias P11ex.Session, as: Session
  alias P11ex.Lib, as: Lib
  alias P11ex.Module, as: Module

  def list_slots(conn) do
    case Module.list_slots(true) do
      {:ok, slots} ->
        {:ok, Enum.map(slots, fn slot ->
          %{
            id: slot.slot_id,
            description: slot.description
          }
        end)}
      {:error, reason} ->
        {:error, reason}
    end
  end


  def generate_random(conn) do
    :poolboy.transaction(P11exBench.SessionPool, fn session ->
      Session.generate_random(session, 10)
    end)
  end


end
