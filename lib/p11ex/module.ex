defmodule P11ex.Module do

  @moduledoc """
  A module is a `GenServer` that manages a PKCS#11 module and its loading state. A PKCS#11 module is a
  shared library that implements a PKCS#11 provider.  A module should be loaded only once per application
  or beam virtual machine. That is, you should only create one instance of `P11ex.Module` in your application
  and add it to your supervision tree. Operations on the module should be performed through the `GenServer`
  callbacks so that they are serialized.

  ## Loading a module

  To load a module, you can use the `start_link/1` function. The argument is the path to the module file.
  The module will be loaded and initialized.

  ```elixir
  defmodule MyApp.Supervisor do
    use Supervisor

    def start_link(init_arg) do
      Supervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
    end

    def init(init_arg) do
      children = [
        {P11ex.Module, "/usr/lib/softhsm/libsofthsm2.so"}
      ]
      Supervisor.init(children, strategy: :one_for_one)
    end
  end
  ```
  """

  use GenServer
  require Logger

  alias P11ex.Lib, as: Lib
  alias P11ex.Lib.Slot, as: Slot

  # Public API

  @doc """
  Start the `P11ex.Module` GenServer. The argument is the path to the
  PKCS#11 module file (shared library).
  """
  @spec start_link(binary()) :: GenServer.on_start()
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

  @doc """
  List all slots in the module. The `token_present?` argument is optional and
  defaults to `true`. If set to `true`, only slots with a token present are returned.
  """
  @spec list_slots(boolean()) :: {:ok, list(Slot.t())} | {:error, atom()}
  def list_slots(token_present?) when is_boolean(token_present?) do
    GenServer.call(__MODULE__, {:list_slots, token_present?})
  end

  @doc """
  Find the slot that contains a token with the given label.
  """
  @spec find_slot_by_tokenlabel(binary()) :: {:ok, Slot.t()} | {:ok, nil} | {:error, atom()}
  def find_slot_by_tokenlabel(label) when is_binary(label) do
    GenServer.call(__MODULE__, {:find_slot_by_tokenlabel, label})
  end

  @doc """
  Get information about a token in a slot. This function has two variants:

  1. `token_info(slot_id)` - Get token info using a slot ID
  2. `token_info(slot)` - Get token info using a Slot struct

  The token information is based on the PKCS#11 structure `CK_TOKEN_INFO` and contains the following fields:

  * `label` - The label of the token (a string)
  * `manufacturer_id` - The manufacturer ID of the token (a string)
  * `model` - The model of the token (a string)
  * `serial_number` - The serial number of the token (a string)
  * `flags` - The flags of the token (a list of atoms, see `P11ex.Flags`)
  * `max_session_count` - The maximum number of sessions that can be opened for the token (an integer)
  * `session_count` - The number of sessions that are currently open for the token (an integer)
  * `max_rw_session_count` - The maximum number of read/write sessions that can be opened for the token (an integer)
  * `rw_session_count` - The number of read/write sessions that are currently open for the token (an integer)
  * `max_pin_len` - The maximum length of the PIN for the token (an integer)
  * `min_pin_len` - The minimum length of the PIN for the token (an integer)
  * `total_public_memory` - The total amount of public memory in the token (an integer)
  * `free_public_memory` - The amount of free public memory in the token (an integer)
  * `total_private_memory` - The total amount of private memory in the token (an integer)
  * `free_private_memory` - The amount of free private memory in the token (an integer)
  * `hardware_version` - The hardware version of the token (a tuple of integers)
  * `firmware_version` - The firmware version of the token (a tuple of integers)
  * `utc_time` - The UTC time of the token (a string)
  """
  @spec token_info(non_neg_integer()) :: {:ok, map()} | {:error, atom()}
  def token_info(slot_id) when is_integer(slot_id) do
    GenServer.call(__MODULE__, {:token_info, %Slot{module: self(), slot_id: slot_id}})
  end

  @spec token_info(Slot.t()) :: {:ok, map()} | {:error, atom()}
  def token_info(%Slot{} = slot) do
    GenServer.call(__MODULE__, {:token_info, slot})
  end

  @doc """
  List all mechanisms supported by the PKCS#11 module for a slot. This function has two variants:

  1. `list_mechanisms(slot_id)` - List mechanisms using a slot ID
  2. `list_mechanisms(slot)` - List mechanisms using a Slot struct

  The mechanisms are returned as a list of atoms. If the mechanism is not known to P11ex
  (e.g. a vendor specific mechanism), it will be returned as an integer.
  """
  @spec list_mechanisms(non_neg_integer()) :: {:ok, list(atom() | non_neg_integer())} | {:error, atom()}
  def list_mechanisms(slot_id) when is_integer(slot_id) do
    GenServer.call(__MODULE__, {:list_mechanisms, %Slot{module: self(), slot_id: slot_id}})
  end

  @spec list_mechanisms(Slot.t()) :: {:ok, list(atom() | non_neg_integer())} | {:error, atom()}
  def list_mechanisms(slot) do
    GenServer.call(__MODULE__, {:list_mechanisms, slot})
  end

  @doc """
  Get information about a mechanism for a given slot. The mechanism is specified
  as an atom or an integer. For example, the mechanism `:ckm_aes_cbc` can also
  be specified as the integer `0x00001082`:

  ```elixir
  {:ok, info} = P11ex.Module.mechanism_info(slot, :ckm_aes_cbc)
  {:ok, info} = P11ex.Module.mechanism_info(slot, 0x00001082)
  ```

  The return value is a map with the following keys:

  * `flags` - The flags of the mechanism (a list of atoms, see `P11ex.Flags`). This
  indicates for what operations the mechanism can be used, e.g. `:encrypt`,
  `:decrypt`, `:sign`, `:verify`, etc.
  * `min_length` - The minimum key length supported by the mechanism (an integer)
  * `max_length` - The maximum key length supported by the mechanism (an integer)

  For example, for `:ckm_aes_cbc` a typical return value is:

  ```elixir
  %{flags: MapSet.new([:wrap, :encrypt, :decrypt]), min_length: 16, max_length: 32}
  ```

  If the mechanism is not known, the return value is
  `{:error, {:C_GetMechanismInfo, :ckr_mechanism_invalid}}`.
  """
  @spec mechanism_info(Slot.t(), atom() | non_neg_integer()) :: {:ok, map()} | {:error, atom()}
  def mechanism_info(slot, mechanism_type) do
    GenServer.call(__MODULE__, {:mechanism_info, slot, mechanism_type})
  end

  def open_session(slot, flags) do
    GenServer.call(__MODULE__, {:open_session, slot, flags})
  end

  @doc """
  Register a successful login for a token in the PKCS#11 slot managed
  by this instance of `P11ex.Module`. User type is `:user` or `:so`
  (security officer). If set, subsequent operations on the token will
  be skipped. This is necessary to avoid login errors of value
  `:ckr_user_already_logged_in`. Can also be set to `nil` to unregister
  a login.
  """
  @spec register_login(atom() | nil) :: :ok
  def register_login(user_type) do
    GenServer.cast(__MODULE__, {:register_login, user_type})
  end

  @doc """
  Check if a successful login has been registered for a token in the
  PKCS#11 slot managed by this instance of `P11ex.Module`. The return value
  is `:user` or `:so` (security officer) if a login has been registered, or
  `nil` if no login has been registered.
  """
  @spec login_type() :: atom() | nil
  def login_type do
    GenServer.call(__MODULE__, :login_type)
  end

  @doc """
  Returns a reference to the handle of the PKCS#11 module. Usually, this
  is not needed by the application, but it can be useful if you need to
  perform operations on the module that are not otherwise provided by this
  library.
  """
  @spec module_handle() :: reference()
  def module_handle do
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
  def handle_call({:list_mechanisms, slot}, _from, state) do
    {:reply, Lib.list_mechanisms(state.handle, slot.slot_id), state}
  end

  @impl true
  def handle_call({:mechanism_info, slot, mechanism_type}, _from, state) do
    {:reply, Lib.mechanism_info(state.handle, slot.slot_id, mechanism_type), state}
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
