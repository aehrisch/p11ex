defmodule P11ex.Session do
  @moduledoc """
  This module is a `GenServer` that manages a PKCS#11 session. A session is used
  to interact with a token, e.g. generate keys, encrypt data, decrypt data, etc. Sessions
  are created by the `P11ex.Module` module using the `open_session/3` function. Depending on
  the type of token multiple for the same token can be opened in parallel (e.g. if the token is
  a network HSM). One session can only be used in a serialised way, i.e. only one operation can be
  performed at a time. Additionally, sessions have a state. This state can be non-persistent keys associated
  with the session or the state of an encryption or decryption operation.

  Technically, most PKCS#11 functions require to login to the token first using a PIN. That is, the
  login state is not connected to a particular session opened on a token. Many tokens raise an `:cka_already_logged_in`
  error if a PIN is provided for a session that is already logged in. The `P11ex.Session` module tries to
  make handling of the login state more easy by tracking the login state of the session. That is, only the
  first call to `login/3` will actually login to the token. Subsequent calls to `login/3` will check if
  the session is already logged in and skip the login if so.

  ## Usage

  The following examples show how to log into a token and create a new session.

  ```elixir
  {:ok, module} = P11ex.Module.start_link("/usr/lib/softhsm/libsofthsm2.so")
  {:ok, slot} = P11ex.Module.find_slot_by_tokenlabel("Token_0")

  {:ok, session} = P11ex.Session.start_link(module: module, slot_id: slot.slot_id, flags: [:rw_session])
  :ok = P11ex.Session.login(session, :user, "1234")
  ```
  """

  use GenServer

  require Logger

  alias P11ex.Lib, as: Lib
  alias P11ex.Module, as: Module
  alias P11ex.Lib.ObjectAttributes, as: ObjectAttributes
  alias P11ex.Lib.ObjectHandle, as: ObjectHandle

  def start_link(args) do
    # Allow starting without a name
    name = Keyword.get(args, :name)
    if name do
      GenServer.start_link(__MODULE__, args, name: name)
    else
      GenServer.start_link(__MODULE__, args)
    end
  end

  @doc """
  Initialize the session `GenServer`. This requires the `:module` (a `P11ex.Lib.ModuleHandle.t()`)
  and the `:slot_id` (an integer) of the slot the session is opened on. Additionally, the `:flags`
  keyword argument can be used to pass additional flags to the `open_session/3` function.
  """
  @impl true
  @spec init(Keyword.t()) :: {:ok, map()} | {:error, atom()}
  def init(args) do

    module = Keyword.fetch!(args, :module)
    slot_id = Keyword.fetch!(args, :slot_id)
    flags = Keyword.get(args, :flags, [:rw_session, :serial_session])

    Logger.info("session init: module_handle=#{inspect(module)}, slot_id=#{slot_id}, flags=#{inspect(flags)}")
    case Lib.open_session(module.module_handle(), slot_id, flags) do
      {:ok, session} ->
        Logger.debug("session opened successfully session=#{inspect(session)}")
        {:ok, %{module: module,
               slot_id: slot_id,
               current_op: nil,
               session: session}}
      {:error, err} ->
        {:stop, err}
    end
  end

  # Public API

  @doc """
  Get information about the session. The result is a map with the following keys:
  * `:slot_id` - the slot ID of the session
  * `:state` - the state of the session
  * `:flags` - the flags of the session
  * `:device_error` - the device error of the session
  """
  @spec info(server :: GenServer.server()) :: {:ok, map()} | {:error, atom()}
  def info(server \\ __MODULE__) do
    GenServer.call(server, :info)
  end

  @doc """
  Login to the session. The `user_type` can be `:user` or `:so`.
  The `pin` is the PIN of the user. The `P11ex.Session` module will check
  if a login already succeeded for the session and skip the login if so. This
  avoids `:cka_already_logged_in` errors.
  """
  @spec login(server :: GenServer.server(), user_type :: atom(), pin :: String.t()) :: :ok | {:error, atom()}
  def login(server \\ __MODULE__, user_type, pin) do
    GenServer.call(server, {:login, user_type, pin})
  end

  @doc """
  Logout from the session.
  """
  @spec logout(server :: GenServer.server()) :: :ok | {:error, atom()}
  def logout(server \\ __MODULE__) do
    GenServer.call(server, :logout)
  end

  @doc """
  Find objects in the session. The `attributes` is a list of tuples where the first
  element is the attribute type and the second element is the value to match. The
  `max_hits` is the maximum number of hits to return. The result is a list of
  `P11ex.Lib.ObjectHandle.t()` objects.

  This example shows how to find all secret keys in the session.

  ```elixir
    {:ok, objects} = P11ex.Session.find_objects(session, [{:cka_class, :cko_secret_key}], 10)
  ```

  To find all secret keys with the label "my_key" use the following:

  ```elixir
    {:ok, objects} = P11ex.Session.find_objects(session, [{:cka_class, :cko_secret_key}, {:cka_label, "my_key"}], 10)
  ```
  """
  @spec find_objects(server :: GenServer.server(), attributes :: [{atom(), any()}], max_hits :: non_neg_integer()) :: {:ok, [ObjectHandle.t()]} | {:error, atom()}
  def find_objects(server \\ __MODULE__, attributes, max_hits)
    when is_list(attributes) and is_integer(max_hits) and max_hits >= 0 do
    GenServer.call(server, {:find_objects, attributes, max_hits})
  end

  def read_object(server \\ __MODULE__, %ObjectHandle{} = object, type_hint \\ nil) do
    GenServer.call(server, {:read_object, object, type_hint})
  end

  def generate_key(server \\ __MODULE__, mechanism, key_template) do
    GenServer.call(server, {:generate_key, mechanism, key_template})
  end

  def encrypt(server \\ __MODULE__, mechanism, %ObjectHandle{} = key, data) do
    GenServer.call(server, {:encrypt, mechanism, key, data})
  end

  def decrypt(server \\ __MODULE__, mechanism, %ObjectHandle{} = key, data) do
    GenServer.call(server, {:decrypt, mechanism, key, data})
  end

  def encrypt_init(server \\ __MODULE__, mechanism, %ObjectHandle{} = key) do
    GenServer.call(server, {:encrypt_init, mechanism, key})
  end

  def encrypt_update(server \\ __MODULE__, data) when is_binary(data) do
    GenServer.call(server, {:encrypt_update, data})
  end

  def encrypt_final(server \\ __MODULE__) do
    GenServer.call(server, :encrypt_final)
  end

  def decrypt_init(server \\ __MODULE__, mechanism, %ObjectHandle{} =key) do
    GenServer.call(server, {:decrypt_init, mechanism, key})
  end

  def decrypt_update(server \\ __MODULE__, data) when is_binary(data) do
    GenServer.call(server, {:decrypt_update, data})
  end

  def decrypt_final(server \\ __MODULE__) do
    GenServer.call(server, :decrypt_final)
  end

  def destroy_object(server \\ __MODULE__, %ObjectHandle{} = object) do
    GenServer.call(server, {:destroy_object, object})
  end

  ###
  ### Implementation of callbacks

  @impl true
  def handle_call(:info, _from, state) do
    res = Lib.session_info(state.session)
    {:reply, res, state}
  end

  @impl true
  def handle_call({:login, user_type, pin}, _from, state) do
    logged_in_as = state.module.login_type()
    Logger.debug("session login #{inspect(user_type)} logged_in_as=#{inspect(logged_in_as)}")
    case logged_in_as do
      ^user_type ->
        Logger.info("already logged in as #{user_type}")
        Module.register_login(user_type)
        {:reply, :ok, state}
      false ->
        case Lib.session_login(state.session, user_type, pin) do
          :ok ->
            Logger.info("logged in as #{user_type}")
            # Notify Module of successful login
            Module.register_login(user_type)
            {:reply, :ok, state}
          err -> {:reply, err, state}
        end
    end
  end

  @impl true
  def handle_call(:logout, _from, state) do
    case Lib.session_logout(state.session) do
      :ok ->
        # Notify Module that we've logged out
        Module.register_login(nil)
        {:reply, :ok, state}
      err -> {:reply, err, state}
    end
  end

  @impl true
  def handle_call({:find_objects, attributes, max_hits}, _from, state) do
    case Lib.find_objects(state.session, attributes, max_hits) do
      {:ok, objects} ->
        {:reply, {:ok, objects}, state}
      err ->
        {:reply, err, state}
    end
  end

  @impl true
  def handle_call({:read_object, %ObjectHandle{} = object, type_hint}, _from, state) do

    fetch_set =
      case type_hint do
        [] -> ObjectAttributes.common()
        nil -> ObjectAttributes.common()
        :cko_key -> ObjectAttributes.key()
        :cko_secret_key -> ObjectAttributes.secret_key()
        [h | t] -> MapSet.new([h | t])
        _ -> ObjectAttributes.storage()
      end
    Logger.debug("initial attribute fetch set: #{inspect(fetch_set)}")

    res = Lib.get_object_attributes(state.session, object, fetch_set)
    {:reply, res, state}
  end

  @impl true
  def handle_call({:generate_key, mechanism, key_template}, _from, state) do
    case Lib.generate_key(state.session, mechanism, key_template) do
      {:ok, object_handle} ->
        {:reply, {:ok, ObjectHandle.new(state.session, object_handle)}, state}
      err ->
        {:reply, err, state}
    end
  end

  @impl true
  def handle_call({:encrypt, mechanism, %ObjectHandle{} = key, data}, _from, state) do
    if state.current_op == nil do
      res = Lib.encrypt(state.session, mechanism, key, data)
      {:reply, res, state}
    else
      {:reply, {:error, :invalid_state}, state}
    end
  end

  @impl true
  def handle_call({:decrypt, mechanism, %ObjectHandle{} = key, data}, _from, state) do
    if state.current_op == nil do
      res = Lib.decrypt(state.session, mechanism, key, data)
      {:reply, res, state}
    else
      {:reply, {:error, :invalid_state}, state}
    end
  end

  @impl true
  def handle_call({:encrypt_init, mechanism, %ObjectHandle{} = key}, _from, state) do
    case Lib.encrypt_init(state.session, mechanism, key) do
      {:ok, op} -> {:reply, {:ok, op}, %{state | current_op: :encrypt}}
      err -> {:reply, err, %{state | current_op: nil}}
    end
  end

  def handle_call({:encrypt_update, data}, _from, state) do
    case Lib.encrypt_update(state.session, data) do
      {:ok, op} -> {:reply, {:ok, op}, state}
      err -> {:reply, err, %{state | current_op: nil}}
    end
  end

  def handle_call(:encrypt_final, _from, state) do
    case Lib.encrypt_final(state.session) do
      {:ok, op} -> {:reply, {:ok, op}, %{state | current_op: nil}}
      err -> {:reply, err, %{state | current_op: nil}}
    end
  end

  def handle_call({:decrypt_init, mechanism, %ObjectHandle{} = key}, _from, state) do
    case Lib.decrypt_init(state.session, mechanism, key) do
      {:ok, op} -> {:reply, {:ok, op}, %{state | current_op: :decrypt}}
      err -> {:reply, err, %{state | current_op: nil}}
    end
  end

  def handle_call({:decrypt_update, data}, _from, state) do
    case Lib.decrypt_update(state.session, data) do
      {:ok, op} -> {:reply, {:ok, op}, state}
      err -> {:reply, err, %{state | current_op: nil}}
    end
  end

  def handle_call(:decrypt_final, _from, state) do
    case Lib.decrypt_final(state.session) do
      {:ok, op} -> {:reply, {:ok, op}, %{state | current_op: nil}}
      err -> {:reply, err, %{state | current_op: nil}}
    end
  end

  @impl true
  def handle_call({:destroy_object, %ObjectHandle{} = object}, _from, state) do
    res = Lib.destroy_object(state.session, object)
    {:reply, res, state}
  end

end
