defmodule P11ex.Module do

  use GenServer
  require Logger

  alias P11ex.Lib, as: Lib

  # Public API

  def start_link(args) do
    GenServer.start_link(__MODULE__, args, name: __MODULE__)
  end

  @impl true
  def init(module_path) when is_binary(module_path) do
    Logger.info("init: module_path=#{module_path}")
    with {:ok, handle} <- Lib.load_module(module_path) do
      Logger.info("init: handle=#{inspect(handle)}")
      {:ok, %{handle: handle, logged_in: false}}
    end
  end

  @impl true
  def terminate(_reason, state) do
    Logger.info("terminate: state=#{inspect(state)}")
    if Map.has_key?(state, :handle) do
      Lib.finalize(state.handle)
    end
  end

  def list_slots(token_present?) when is_boolean(token_present?) do
    GenServer.call(__MODULE__, {:list_slots, token_present?})
  end

  def find_slot_by_tokenlabel(label) when is_binary(label) do
    GenServer.call(__MODULE__, {:find_slot_by_tokenlabel, label})
  end

  def token_info(slot) do
    GenServer.call(__MODULE__, {:token_info, slot})
  end

  def open_session(slot, flags) do
    GenServer.call(__MODULE__, {:open_session, slot, flags})
  end

  def register_login(user_type) do
    GenServer.cast(__MODULE__, {:register_login, user_type})
  end

  def login_type() do
    GenServer.call(__MODULE__, :login_type)
  end

  def module_handle()  do
    GenServer.call(__MODULE__, :module_handle)
  end

  # Implementation of the GenServer callbacks

  @impl true
  def handle_call({:list_slots, token_present?}, _from, state) do
    {:reply, Lib.list_slots(state.handle, token_present?), state}
  end

  @impl true
  def handle_call({:find_slot_by_tokenlabel, label}, _from, state) do
    case Lib.list_slots(state.handle, true) do
      {:ok, slots} ->
        matched_slot = slots
          |> Enum.map(fn slot ->
              case Lib.token_info(slot.module, slot.slot_id) do
                {:ok, token_info} -> {:ok, token_info, slot}
                {:error, reason} -> {:error, slot.slot_id, reason}
              end
            end)
          |> Enum.find(nil, fn {:ok, token_info, _slot_id} -> token_info.label == label end)
        case matched_slot do
          nil ->
            Logger.info("no slot found with token label #{label}")
            {:reply, {:ok, nil}, state}
          {:ok, _token_info, slot} ->
            Logger.info("found slot with #{slot.slot_id} which has token label #{label}")
            {:reply, {:ok, slot}, state}
        end
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:token_info, slot}, _from, state) do
    {:reply, Lib.token_info(state.handle, slot.slot_id), state}
  end

  @impl true
  def handle_call({:open_session, slot_id, flags}, _from, state) do
    {:reply, Lib.open_session(state.handle, slot_id, flags), state}
  end

  @impl true
  def handle_call({:register_login, user_type}, _from, state) do
    {:reply, {:ok, %{state | logged_in: user_type}}, state}
  end

  @impl true
  def handle_call(:module_handle, _from, state) do
    {:reply, state.handle, state}
  end

  @impl true
  def handle_call(:login_type, _from, state) do
    {:reply, state.logged_in, state}
  end

  @impl true
  def handle_cast({:register_login, user_type}, state) do
    {:noreply, %{state | logged_in: user_type}}
  end

end
