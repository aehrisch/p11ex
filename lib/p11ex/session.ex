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
  alias P11ex.Lib.ObjectAttributes, as: ObjectAttributes
  alias P11ex.Lib.ObjectHandle, as: ObjectHandle
  alias P11ex.Module, as: Module

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
  Log in to the session. The `user_type` must be either `:user` or `:so`. Provide the user's pin
  for authentication. The `P11ex.Session` module checks if the session is already logged in and
  skips the login if so, preventing `:cka_already_logged_in` errors.
  """
  @spec login(server :: GenServer.server(), user_type :: {:user, :so}, pin :: String.t()) :: :ok | {:error, atom()}
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

  @doc """
  Read the attributes of the object identified by object handle `object`. The `type_hint`
  is an optional and can be used to specify the attributes to read. The default is to read
  the common attributes (e.g. `:cka_class`, `:cka_id`). See `P11ex.Lib.ObjectAttributes`
  for commonly used attribute sets.

  The function returns a map of the successfully read attributes. The attributes that
  could not be read (but were requested through the `type_hint`) are returned as the
  second element of the tuple. Reasons for not retrieving the attributes are that the
  attributes are not set or are sensitive.
  """
  @spec read_object(server :: GenServer.server(), object :: ObjectHandle.t(), type_hint :: [atom()] | nil)
    :: {:ok, map(), [atom()]} | {:error, atom()} | {:error, atom(), any()}
  def read_object(server \\ __MODULE__, %ObjectHandle{} = object, type_hint \\ nil) do
    GenServer.call(server, {:read_object, object, type_hint})
  end

  def generate_key(server \\ __MODULE__, mechanism, key_template) do
    GenServer.call(server, {:generate_key, mechanism, key_template})
  end

  @doc """
  Encrypt data using the specified `mechanism` and `key` in a single call. See
  `P11ex.Lib.encrypt/4` on how to select an encryption mechanism and
  set its parameters.
  """
  @spec encrypt(
    server :: GenServer.server(),
    mechanism :: Lib.mechanism_instance(),
    key :: ObjectHandle.t(),
    data :: binary())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def encrypt(server \\ __MODULE__, mechanism, %ObjectHandle{} = key, data) do
    GenServer.call(server, {:encrypt, mechanism, key, data})
  end

  @doc """
  Initialize an encryption operation involving the specified `mechanism` and `key`.
  Use `P11ex.Session.encrypt_update/2` and `P11ex.Session.encrypt_final/1` to provide
  the data to encrypt and produce the ciphertext chunks. Note that only one encryption
  operation can be active at a time for a given session. Consider using `P11ex.Session.encrypt/4`
  if you want to encrypt data in a single call and the data is not too large.

  The function returns `:ok` if the operation is initialized successfully. That is, no
  other operations (e.g. decryption, signing, etc.) can be active at the same time.

  Many mechanisms require additional parameters. See `P11ex.Lib.encrypt_init/3` for more
  information on mechanisms and their parameters.
  """
  @spec encrypt_init(
    server :: GenServer.server(),
    Lib.mechanism_instance(), ObjectHandle.t())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def encrypt_init(server \\ __MODULE__, mechanism, %ObjectHandle{} = key) do
    GenServer.call(server, {:encrypt_init, mechanism, key})
  end

  @doc """
  Provide a chunk of plaintext data to the encryption operation that is in
  progress for this session (see `P11ex.Session.encrypt_init/3`).
  """
  @spec encrypt_update(
    server :: GenServer.server(),
    data :: binary())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def encrypt_update(server \\ __MODULE__, data) when is_binary(data) do
    GenServer.call(server, {:encrypt_update, data})
  end

  @doc """
  Finalize the encryption operation that is in progress for this session.
  """
  def encrypt_final(server \\ __MODULE__) do
    GenServer.call(server, :encrypt_final)
  end

  @doc """
  Decrypt data using the specified `mechanism` and `key` in a single call. See
  `P11ex.Lib.encrypt_init/3` on how to select a decryption mechanism and
  set its parameters. Consider using `P11ex.Session.decrypt_init/3`,
  `P11ex.Session.decrypt_update/2`, and `P11ex.Session.decrypt_final/1` if you
  want to decrypt data in chunks.
  """
  @spec decrypt(
    server :: GenServer.server(),
    mechanism :: Lib.mechanism_instance(),
    key :: ObjectHandle.t(),
    data :: binary())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def decrypt(server \\ __MODULE__, mechanism, %ObjectHandle{} = key, data) do
    GenServer.call(server, {:decrypt, mechanism, key, data})
  end

  @doc """
  Initialize a decryption operation involving the specified `mechanism` and `key`. Many
  mechanisms require additional parameters. See `P11ex.Lib.encrypt_init/3` for more
  information on mechanisms and their parameters.

  The function returns `:ok` if the operation is initialized successfully. The session
  is now in decryption mode and no other operations can be active at the same time. The
  ciphertext can be provided in chunks using `P11ex.Session.decrypt_update/2` and
  `P11ex.Session.decrypt_final/1`.

  Consider using `P11ex.Session.decrypt/4` if you want to decrypt data in a single call.
  """
  @spec decrypt_init(
    server :: GenServer.server(),
    mechanism :: Lib.mechanism_instance(),
    key :: ObjectHandle.t())
      :: :ok | {:error, atom()} | {:error, atom(), any()}
  def decrypt_init(server \\ __MODULE__, mechanism, %ObjectHandle{} = key) do
    GenServer.call(server, {:decrypt_init, mechanism, key})
  end

  @doc """
  Provide a chunk of ciphertext data to the decryption operation that is in
  progress for this session (see `P11ex.Session.decrypt_init/3`).
  """
  @spec decrypt_update(
    server :: GenServer.server(),
    data :: binary())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def decrypt_update(server \\ __MODULE__, data) when is_binary(data) do
    GenServer.call(server, {:decrypt_update, data})
  end

  @doc """
  Finalize the decryption operation that is in progress for this session
  (see `P11ex.Session.decrypt_init/3`).
  """
  @spec decrypt_final(server :: GenServer.server())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def decrypt_final(server \\ __MODULE__) do
    GenServer.call(server, :decrypt_final)
  end

  @doc """
  Initialize a signing operation or MAC computation involving
  the specified `mechanism` and `key`. The key type must be suitable for
  the specified `mechanism`. If the initialization is successful, the
  session's current operation is set to `:sign`. This operation can be
  finalized by calling `sign_final/1` or `sign/2`. Also, a failure of
  `sign_update/2` will end this state.
  """
  @spec sign_init(server :: GenServer.server(), Lib.mechanism_instance(), ObjectHandle.t())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def sign_init(server \\ __MODULE__, mechanism, %ObjectHandle{} = key)
      when is_tuple(mechanism) do
    GenServer.call(server, {:sign_init, mechanism, key})
  end

  @doc """
  Sign or MAC data. The session must be in the `:sign` state, so this function
  must be called after `sign_init/3`. If the operation fails, the session's
  current operation is reset. The function returns the signature or MAC.
  """
  @spec sign(server :: GenServer.server(), binary())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def sign(server \\ __MODULE__, data) when is_binary(data) do
    GenServer.call(server, {:sign, data})
  end

  @doc """
  Provide data to the signing operation or MAC computation. The session must
  be in the `:sign` state, so this function must be called after `sign_init/3`.
  Call this function repeatedly with chunks of data until all data has been
  provided. If the operation fails, the session's current operation is reset.
  """
  @spec sign_update(server :: GenServer.server(), binary())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def sign_update(server \\ __MODULE__, data) when is_binary(data) do
    GenServer.call(server, {:sign_update, data})
  end

  @doc """
  Finalize the signing operation or MAC computation. The session must
  be in the `:sign` state, so this function must be called after
  `sign_init/3` and `sign_update/2`. If the operation fails, the session's
  current operation is reset. The function returns the signature or MAC.
  """
  @spec sign_final(server :: GenServer.server())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def sign_final(server \\ __MODULE__) do
    GenServer.call(server, :sign_final)
  end

  @spec verify_init(server :: GenServer.server(), Lib.mechanism_instance(), ObjectHandle.t())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def verify_init(server \\ __MODULE__, mechanism, %ObjectHandle{} = key)
      when is_tuple(mechanism) do
    GenServer.call(server, {:verify_init, mechanism, key})
  end

  @spec verify(server :: GenServer.server(), binary(), binary())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def verify(server \\ __MODULE__, data, signature)
      when is_binary(data) and is_binary(signature) do
    GenServer.call(server, {:verify, data, signature})
  end

  @doc """
  Initialize a digest operation involving the specified `mechanism`. The session's
  current operation is set to `:digest`. This operation can be finalized by calling
  `digest_final/1` or `digest/1`. Also, a failure of `digest_update/2` will end
  this state.

  ## Example: Digest computation in chunks

  ```elixir
  :ok = P11ex.Session.digest_init(session, {:ckm_sha256})
  :ok = P11ex.Session.digest_update(session, data1)
  :ok = P11ex.Session.digest_update(session, data2)
  {:ok, digest} = P11ex.Session.digest_final(session)
  ```

  ## Example: Digest computation in one go

  ```elixir
  :ok = P11ex.Session.digest_init(session, {:ckm_sha256})
  {:ok, digest} = P11ex.Session.digest(session, data)
  ```
  """
  @spec digest_init(GenServer.server(), Lib.mechanism_instance())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def digest_init(server \\ __MODULE__, mechanism)
      when is_tuple(mechanism) do
    GenServer.call(server, {:digest_init, mechanism})
  end

  @doc """
  Provide data to the digest operation. The session must be in the `:digest` state,
  so this function must be called after `digest_init/2`. Call this function repeatedly
  with chunks of data until all data has been provided. If the operation fails, the
  session's current operation is reset.
  """
  @spec digest_update(server :: GenServer.server(), binary())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def digest_update(server \\ __MODULE__, data) do
    GenServer.call(server, {:digest_update, data})
  end

  @doc """
  Finalize the digest operation. The session must be in the `:digest` state,
  so this function must be called after `digest_init/2` and `digest_update/2`.
  If the operation fails, the session's current operation is reset. The function
  returns the digest.
  """
  @spec digest_final(server :: GenServer.server())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def digest_final(server \\ __MODULE__) do
    GenServer.call(server, :digest_final)
  end

  @doc """
  Get the digest of the data provided to the digest operation. The session must be in the
  `:digest` state, so this function must be called after `digest_init/2`.
  """
  @spec digest(server :: GenServer.server(), binary())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def digest(server \\ __MODULE__, data)
      when is_binary(data) do
    GenServer.call(server, {:digest, data})
  end

  @doc """
  Destroy the object specified by `object`.
  """
  @spec destroy_object(server :: GenServer.server(), ObjectHandle.t())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def destroy_object(server \\ __MODULE__, %ObjectHandle{} = object) do
    GenServer.call(server, {:destroy_object, object})
  end

  @doc """
  Generate random data.
  """
  @spec generate_random(server :: GenServer.server(), len :: non_neg_integer())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def generate_random(server \\ __MODULE__, len)
      when is_integer(len) and len > 0 do
    GenServer.call(server, {:generate_random, len})
  end

  @spec generate_key_pair(server :: GenServer.server(), Lib.mechanism_instance(), Lib.attributes(), Lib.attributes())
    :: {:ok, {ObjectHandle.t(), ObjectHandle.t()}} | {:error, atom()} | {:error, atom(), any()}
  def generate_key_pair(server \\ __MODULE__, mechanism,
      pub_key_template, priv_key_template)
      when is_tuple(mechanism) do
    GenServer.call(server, {:generate_key_pair, mechanism, pub_key_template, priv_key_template})
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
        :cko_public_key -> ObjectAttributes.public_key()
        :cko_private_key -> ObjectAttributes.private_key()
        :cko_secret_key -> ObjectAttributes.secret_key()
        [h | t] -> MapSet.new([h | t])
        ms when is_struct(ms, MapSet) -> ms
        _ -> ObjectAttributes.storage()
      end
    Logger.debug("initial attribute fetch set: #{inspect(fetch_set)}")

    res = Lib.get_object_attributes(state.session, object, fetch_set)
    {:reply, res, state}
  end

  @impl true
  def handle_call({:generate_key, mechanism, key_template}, _from, state) do
    case Lib.generate_key(state.session, mechanism, key_template) do
      {:ok, obj} ->
        {:reply, {:ok, obj}, state}
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
  def handle_call({:sign_init, mechanism, %ObjectHandle{} = key}, _from, state)
      when is_tuple(mechanism) do
    case Lib.sign_init(state.session, mechanism, key) do
      :ok -> {:reply, :ok, %{state | current_op: :sign}}
      err -> {:reply, err, %{state | current_op: nil}}
    end
  end

  @impl true
  def handle_call({:sign, data}, _from, state)
      when is_binary(data) do
    case Lib.sign(state.session, data) do
      {:ok, sig} -> {:reply, {:ok, sig}, %{state | current_op: nil}}
      err -> {:reply, err, %{state | current_op: nil}}
    end
  end

  @impl true
  def handle_call({:sign_update, data}, _from, state)
      when is_binary(data) do
    case Lib.sign_update(state.session, data) do
      :ok -> {:reply, :ok, %{state | current_op: :sign}}
      err -> {:reply, err, %{state | current_op: nil}}
    end
  end

  @impl true
  def handle_call(:sign_final, _from, state) do
    case Lib.sign_final(state.session) do
      {:ok, sig} -> {:reply, {:ok, sig}, %{state | current_op: nil}}
      err -> {:reply, err, %{state | current_op: nil}}
    end
  end

  @impl true
  def handle_call({:verify_init, mechanism, %ObjectHandle{} = key}, _from, state)
      when is_tuple(mechanism) do
    case Lib.verify_init(state.session, mechanism, key) do
      :ok -> {:reply, :ok, %{state | current_op: :verify}}
      err -> {:reply, err, %{state | current_op: nil}}
    end
  end

  @impl true
  def handle_call({:verify, data, signature}, _from, state)
      when is_binary(data) and is_binary(signature) do
    case Lib.verify(state.session, data, signature) do
      :ok -> {:reply, :ok, %{state | current_op: nil}}
      err -> {:reply, err, %{state | current_op: nil}}
    end
  end

  @impl true
  def handle_call({:digest_init, mechanism}, _from, state)
      when is_tuple(mechanism) do
    case Lib.digest_init(state.session, mechanism) do
      :ok -> {:reply, :ok, %{state | current_op: :digest}}
      err -> {:reply, err, %{state | current_op: nil}}
    end
  end

  @impl true
  def handle_call({:digest_update, data}, _from, state)
      when is_binary(data) do
    case Lib.digest_update(state.session, data) do
      :ok -> {:reply, :ok, %{state | current_op: :digest}}
      err -> {:reply, err, %{state | current_op: nil}}
    end
  end

  @impl true
  def handle_call(:digest_final, _from, state) do
    case Lib.digest_final(state.session) do
      {:ok, digest} -> {:reply, {:ok, digest}, %{state | current_op: nil}}
      err -> {:reply, err, %{state | current_op: nil}}
    end
  end

  @impl true
  def handle_call({:digest, data}, _from, state)
      when is_binary(data) do
    case Lib.digest(state.session, data) do
      {:ok, digest} -> {:reply, {:ok, digest}, state}
      err -> {:reply, err, state}
    end
  end

  @spec generate_random(server :: GenServer.server(), len :: non_neg_integer())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  @impl true
  def handle_call({:generate_random, len}, _from, state)
      when is_integer(len) and len > 0 do
    case Lib.generate_random(state.session, len) do
      {:ok, random} -> {:reply, {:ok, random}, state}
      err -> {:reply, err, state}
    end
  end

  @impl true
  def handle_call({:destroy_object, %ObjectHandle{} = object}, _from, state) do
    res = Lib.destroy_object(state.session, object)
    {:reply, res, state}
  end

  @impl true
  def handle_call({:generate_key_pair, mechanism, pub_key_template, priv_key_template}, _from, state)
      when is_tuple(mechanism) do
    case Lib.generate_key_pair(state.session, mechanism, pub_key_template, priv_key_template) do
      {:ok, pub_key_handle, priv_key_handle} -> {:reply, {:ok, pub_key_handle, priv_key_handle}, state}
      err -> {:reply, err, state}
    end
  end

end
