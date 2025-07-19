defmodule P11ex.Lib do
  @moduledoc """
  This module contains the core functionality for the `P11ex` library and provides
  the low-level API for interacting with PKCS#11 modules. In general, you should not
  use this module directly. Instead, use the higher-level `P11ex.Module` and `P11ex.Session`
  modules instead.
  """

  require Logger

  defmodule ModuleHandle do
    @moduledoc """
    Represents a reference to a dynamically loaded PKCS#11 module.
    """

    @typedoc """
    The path to the shared PKCS#11 library module file. Must always be a valid string.
    """
    @type path :: String.t()

    @typedoc """
    NIF reference to the loaded PKCS#11 module.
    """
    @type ref :: reference()

    @typedoc """
    A struct representing a loaded PKCS#11 module.

    ## Fields:
      - `path` (String.t()): The file path of the module (always required).
      - `ref` (reference()): A NIF reference to the loaded module.
    """
    @type t :: %__MODULE__{path: path(), ref: ref()}

    @enforce_keys [:path, :ref]
    defstruct path: "", ref: nil
  end

  defmodule Slot do
    @moduledoc """
    Represents a PKCS#11 slot. A slot can contain a token (e.g. a smart card) or a token emulator
    (e.g. a software token).
    """

    @typedoc """
    The PKCS#11 module that the slot belongs to.
    """
    @type pkcs11_module :: P11ex.Lib.ModuleHandle.t()

    @typedoc """
    The slot identifier.
    """
    @type slot_id :: non_neg_integer()

    @typedoc """
    The slot description.
    """
    @type description :: String.t()

    @typedoc """
    The manufacturer ID of the slot.
    """
    @type manufacturer_id :: String.t()

    @typedoc """
    The hardware version of the slot.
    """
    @type hardware_version :: {non_neg_integer(), non_neg_integer()}

    @typedoc """
    The firmware version of the slot.
    """
    @type firmware_version :: {non_neg_integer(), non_neg_integer()}

    @typedoc """
    The flags of the slot. See `P11ex.Flags` for more information.
    """
    @type flags :: MapSet.t(atom())

    @typedoc """
    A struct representing a PKCS#11 slot.
    """
    @type t :: %__MODULE__{
      module: pkcs11_module(),
      slot_id: slot_id(),
      description: description(),
      manufacturer_id: manufacturer_id(),
      hardware_version: hardware_version(),
      firmware_version: firmware_version(),
      flags: flags()
    }

    @enforce_keys [:module, :slot_id]
    defstruct [:module, :slot_id, :description, :manufacturer_id, :hardware_version, :firmware_version, :flags]
  end

  defmodule SessionHandle do
    @moduledoc """
    Represents a PKCS#11 session. A session is used to interact with a token.
    """

    @typedoc """
    The PKCS#11 module that the session belongs to.
    """
    @type pkcs11_module :: P11ex.Lib.ModuleHandle.t()

    @typedoc """
    The handle of the session.
    """
    @type handle :: non_neg_integer()

    @typedoc """
    The slot identifier of the session.
    """
    @type slot_id :: non_neg_integer()

    @typedoc """
    A struct representing a PKCS#11 session.
    """
    @type t :: %__MODULE__{
      module: pkcs11_module(),
      handle: handle(),
      slot_id: slot_id()
    }

    defstruct [:module, :handle, :slot_id]

    @doc """
    Create a new session handle.
    """
    @spec new(pkcs11_module(), handle(), slot_id()) :: t()
    def new(%ModuleHandle{} = module, handle, slot_id)
        when is_integer(handle) and handle >= 0 and
             is_integer(slot_id) and slot_id >= 0 do
      %__MODULE__{module: module, handle: handle, slot_id: slot_id}
    end

    def new(_, _, _) do
      raise ArgumentError, "arguments must be a module handle, a handle and a slot id"
    end
  end

  defmodule ObjectHandle do
    @moduledoc """
    Represents a PKCS#11 object. This can be a key, a certificate, a secret key, etc. Note
    that the object handle may be only valid in the context of the session that created it.
    For example, a session key (`:cka_token` is `false`) is only visible and usable within the
    context of the session that generates it. Other handles may be visible and usable over multiple
    sessions, such as handles to token objects.
    """

    @typedoc """
    The PKCS#11 session that the object belongs to. May be `nil` if the is not known
    which session the object belongs to.
    """
    @type session :: P11ex.Lib.SessionHandle.t() | nil

    @typedoc """
    The handle of the object which is unsigned integer identifying the object.
    """
    @type handle :: non_neg_integer()

    @typedoc """
    A struct representing a PKCS#11 object.
    """
    @type t :: %__MODULE__{
      session: session(),
      handle: handle()
    }
    @enforce_keys [:session, :handle]
    defstruct [:session, :handle]

    @doc """
    Create a new object handle and associate it with a session.
    """
    @spec new(session(), handle()) :: t()
    def new(%SessionHandle{} = session, handle)
        when is_integer(handle) and handle >= 0 do
      %__MODULE__{session: session, handle: handle}
    end

    @doc """
    Create a new object handle and do not associate it with a session.
    """
    @spec new(handle()) :: t()
    def new(handle) when is_integer(handle) and handle >= 0 do
      %__MODULE__{session: nil, handle: handle}
    end
  end

  defmodule ObjectAttributes do
    @moduledoc """
    This module defines sets of attributes for PKCS#11 objects.
    """

    @doc """
    Attributes that all kinds of objects have.
    """
    @spec common() :: MapSet.t(atom())
    def common, do: MapSet.new([:cka_class])

    @doc """
    Attributes related to the storage of objects. Most objects have these attributes.
    """
    @spec storage() :: MapSet.t(atom())
    def storage, do: MapSet.union(common(),
        MapSet.new([:cka_label, :cka_modifiable, :cka_private, :cka_token]))

    @doc """
    Attributes related to keys. This are attributes can be found on secrets keys,
    public keys, and private keys.
    """
    @spec key() :: MapSet.t(atom())
    def key do
      MapSet.union(storage(),
        MapSet.new([:cka_derive, :cka_end_date, :cka_id,
                    :cka_id, :cka_key_gen_mechanism, :cka_key_type,
                    :cka_local, :cka_start_date]))
    end

    @doc """
    Attributes that can be found on secret keys.
    """
    @spec secret_key() :: MapSet.t(atom())
    def secret_key do
      MapSet.union(key(),
        MapSet.new([:cka_always_sensitive, :cka_check_value,
          :cka_decrypt, :cka_encrypt,
          :cka_extractable, :cka_never_extractable,
          :cka_sign, :cka_trusted,
          :cka_unwrap, :cka_verify,
          :cka_wrap, :cka_wrap_with_trusted,
          :cka_value_len]))
    end

    @doc """
    Attributes that can be found on public keys.
    """
    @spec public_key() :: MapSet.t(atom())
    def public_key do
      MapSet.union(key(),
        MapSet.new([
          :cka_encrypt,
          :cka_subject,
          :cka_trusted,
          :cka_verify,
          :cka_wrap]))
    end

    @doc """
    Attributes that can be found on RSA public keys.
    """
    @spec rsa_public_key() :: MapSet.t(atom())
    def rsa_public_key do
      MapSet.union(public_key(),
        MapSet.new([:cka_modulus, :cka_modulus_bits, :cka_public_exponent]))
    end

    @doc """
    Attributes that can be found on EC public keys.
    """
    @spec ec_public_key() :: MapSet.t(atom())
    def ec_public_key do
      MapSet.union(public_key(),
        MapSet.new([:cka_ec_params, :cka_ec_point]))
    end

    @doc """
    Attributes that can be found on private keys.
    """
    @spec private_key() :: MapSet.t(atom())
    def private_key do
      MapSet.union(key(),
        MapSet.new([
          :cka_always_authenticate,
          :cka_always_sensitive,
          :cka_decrypt,
          :cka_extractable,
          :cka_never_extractable,
          :cka_sensitive,
          :cka_sign,
          :cka_sign_recover,
          :cka_unwrap,
          :cka_wrap_with_trusted
        ]))
    end

    @doc """
    Attributes that can be found on RSA private keys.
    """
    @spec rsa_private_key() :: MapSet.t(atom())
    def rsa_private_key do
      MapSet.union(private_key(),
        MapSet.new([
          :cka_modulus,
          :cka_public_exponent
        ]))
    end

    @doc """
    Attributes that can be found on EC private keys.
    """
    @spec ec_private_key() :: MapSet.t(atom())
    def ec_private_key do
      MapSet.union(private_key(),
        MapSet.new([:cka_ec_params]))
    end

    @doc """
    Attributes that can be found on RSA private keys that are sensitive. The token will
    not return these attributes unless the `:cka_sensitive` attribute is set to `false`
    or `:cka_extractable` is set to `true`.
    """
    @spec rsa_private_key_with_sensitive() :: MapSet.t(atom())
    def rsa_private_key_with_sensitive do
      MapSet.union(rsa_private_key(),
        MapSet.new([
          :cka_private_exponent,
          :cka_prime_1,
          :cka_prime_2,
          :cka_coefficient,
          :cka_exponent_1,
          :cka_exponent_2
        ]))
    end

  end

  @typedoc """
  A mechanism instance represents a cryptographic mechanism with the
  associated parameters. A mechanism can either be identified by an
  atom (e.g. `:aes_cbc`) or a non-negative integer (e.g. `1`). Some
  mechanisms require additional parameters that are passed as a map.

  Example:
  ```elixir
  {:ckm_aes_cbc, %{iv: iv}}
  ```
  This is AES in CBC mode with the initialization vector `iv`
  (a binary of 16 bytes).

  See `P11ex.Session.encrypt_init/3` for examples on how to set the
  parameters for the various encryption mechanisms.
  """
  @type mechanism_instance ::
      {atom()}
      | {non_neg_integer()}
      | {atom(), map()}
      | {non_neg_integer(), map()}

  @type attribute ::
    {atom()}
    | {atom(), binary()}
    | {atom(), integer()}
    | {atom(), boolean()}

  @type attributes :: list(attribute())

  @spec load_module(String.t()) :: {:ok, ModuleHandle.t()} | {:error, String.t()}
  def load_module(path) do
    Logger.info("Loading PKCS#11 module: #{path}")

    # Try to load NIF if not already loaded
    case :code.priv_dir(:p11ex) do
      {:error, :bad_name} ->
        Logger.warning("p11ex application not loaded, cannot load NIF")
        {:error, "p11ex application not loaded"}
      priv_dir when is_list(priv_dir) ->
        case :erlang.load_nif(:filename.join(priv_dir, "p11ex_nif"), 0) do
          :ok ->
            Logger.debug("NIF loaded successfully")
          {:error, {:load_failed, _}} ->
            Logger.warning("NIF already loaded or failed to load")
          {:error, {:bad_lib, _}} ->
            Logger.warning("NIF library not found")
        end

        with {:ok, ref} <- n_load_module(String.to_charlist(path)) do
          Logger.debug("n_load_module returned ref=#{inspect(ref)}")
          {:ok, %ModuleHandle{path: path, ref: ref}}
        end
    end
  end

  def list_slots(module, token_present) do
    with {:ok, slots} <- n_list_slots(module.ref, token_present) do
      maps = Enum.map(slots, fn slot -> slot_to_map(module, slot) end)
      {:ok, maps}
    end
  end

  def token_info(module, slot_id) do
    with {:ok, raw_token_info} <- n_token_info(module.ref, slot_id) do
      token_info =
        raw_token_info
        |> Map.replace_lazy(:flags, fn flags -> P11ex.Flags.to_atoms(:token, flags) end)
        |> Map.replace_lazy(:manufacturer_id, fn id -> frob_fixedlen_string(id) end)
        |> Map.replace_lazy(:model, fn desc -> frob_fixedlen_string(desc) end)
        |> Map.replace_lazy(:serial_number, fn serial -> frob_fixedlen_string(serial) end)
        |> Map.replace_lazy(:label, fn label -> frob_fixedlen_string(label) end)
        |> Map.replace_lazy(:utc_time, fn utc_time -> frob_utc_date_str(utc_time) end)
      {:ok, token_info}
    end
  end

  def finalize(module) do
    n_finalize(module.ref)
  end

  def open_session(%ModuleHandle{} = module, slot_id, flags)
      when is_integer(slot_id) and slot_id >= 0 do
    flag_num = P11ex.Flags.from_atoms(:session, flags)
    with {:ok, handle} <- n_open_session(module.ref, slot_id, flag_num) do
      {:ok, SessionHandle.new(module, handle, slot_id)}
    end
  end

  def close_session(%SessionHandle{} = session) do
    n_close_session(session.module.ref(), session.handle)
  end

  def close_all_sessions(%ModuleHandle{} = module, slot_id)
      when is_integer(slot_id) and slot_id >= 0 do
    n_close_all_sessions(module.ref, slot_id)
  end

  def session_info(%SessionHandle{} = session) do
    with {:ok, session_info} <- n_session_info(session.module.ref, session.handle) do
      # Convert the session flags to atoms
      session_info =
        session_info
        |> Map.update!(:flags, fn flags -> P11ex.Flags.to_atoms(:session, flags) end)
        |> Map.update!(:state, fn state -> P11ex.Flags.to_atoms(:session_state, state) end)
      {:ok, session_info}
    end
  end

  @spec session_login(SessionHandle.t(), atom(), binary())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def session_login(%SessionHandle{} = session, user_type, pin)
      when is_atom(user_type) and is_binary(pin) do
    user_type_flag = P11ex.Flags.from_atoms(:user_type, MapSet.new([user_type]))
    Logger.info("logging in to session #{inspect(session)} as #{user_type}")
    n_session_login(session.module.ref, session.handle,
                    user_type_flag, String.to_charlist(pin))
  end

  @spec session_logout(SessionHandle.t())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def session_logout(%SessionHandle{} = session) do
    n_session_logout(session.module.ref(), session.handle)
  end

  defp slot_to_map(%ModuleHandle{} = module, n_slot) do
    with {slot_id, desc, manufacturer_id, hardware_version, firmware_version, flags} <- n_slot do
      %Slot{
        module: module,
        slot_id: slot_id,
        description: frob_fixedlen_string(desc),
        manufacturer_id: frob_fixedlen_string(manufacturer_id),
        hardware_version: hardware_version,
        firmware_version: firmware_version,
        flags: P11ex.Flags.to_atoms(:slot, flags) |> MapSet.to_list()
      }
    end
  end

  @known_bigint_attributes MapSet.new([
    :cka_modulus,
    :cka_prime1,
    :cka_prime2,
    :cka_exponent_1,
    :cka_exponent_2,
    :cka_coefficient,
    :cka_public_exponent])

  defp encode_bigint_attribute({name, value})
    when is_atom(name) and is_integer(value) do
      {:ok, {name, :binary.encode_unsigned(value)}}
  end

  defp pre_convert_attribute({name, _} = attrib) do
    if MapSet.member?(@known_bigint_attributes, name) do
      encode_bigint_attribute(attrib)
    else
      {:ok, attrib}
    end
  end

  defp process_attributes(attributes) when is_list(attributes) do
    attributes
    |> Enum.map(fn a -> pre_convert_attribute(a) end)
    |> Enum.reduce({:ok, []}, fn a, {:ok, acc} ->
      case a do
        {:ok, {n, value}} -> {:ok, [{n, value} | acc]}
        {:error, err} -> {:error, err}
      end
    end)
  end

  def find_objects(%SessionHandle{} = session, attributes, max_hits)
      when is_list(attributes) and is_integer(max_hits) and max_hits >= 0 do
    with {:ok, attributes} <- process_attributes(attributes),
         {:ok, handles} <- n_find_objects(session.module.ref, session.handle, attributes, max_hits) do
      {:ok, Enum.map(handles, fn handle -> ObjectHandle.new(session, handle) end)}
    end
  end

  @doc """
  Generate a symmetric key in the session. The key is generated according to the specified `mechanism`
  and the `key_template`. The `key_template` is a list of attributes that will be used to generate
  the key. The function returns a handle to the generated key.

  ## Example: Generate a 128-bit AES key

  The following example generates a 128-bit AES key with the label "test_key" and a random
  key ID. The key is a session key.

  ```elixir
  key_id = :crypto.strong_rand_bytes(16)
  {:ok, key} =
    Session.generate_key(context.session_pid,
      {:ckm_aes_key_gen},
      [
        {:cka_token, false},
        {:cka_label, "test_key"},
        {:cka_value_len, key_id},
        {:cka_id, key_id},
        {:cka_encrypt, true},
        {:cka_decrypt, false},
        {:cka_derive, false},
        {:cka_sign, false}
      ])
  ```
  """
  def generate_key(%SessionHandle{} = session, mechanism, key_template)
      when is_list(key_template) do
    Logger.debug("generate_key: session=#{inspect(session)}, mechanism=#{inspect(mechanism)}, key_template=#{inspect(key_template)}")
    with {:ok, attributes} <- process_attributes(key_template) do
      case n_generate_key(session.module.ref, session.handle, mechanism, attributes) do
        {:ok, handle} -> {:ok, ObjectHandle.new(session, handle)}
        error -> error
      end
    end
  end

  defp post_convert_attributes(attribute_map) do
    attribute_map
    |> Enum.map(fn {name, value} ->
      if MapSet.member?(@known_bigint_attributes, name) do
        {name, :binary.decode_unsigned(value)}
      else
        {name, value}
      end
    end)
    |> Map.new()
  end

  # This is a helper function that parses the list of attributes returned by `n_get_object_attributes/4`
  # and returns a map of valid attributes and a list of errors.
  @spec split_attributes(list(attribute())) :: {map(), list()}
  defp split_attributes(lst) do
    Enum.reduce(lst, {Map.new(), []}, fn a, {ok_set, err_set}  ->
      case a do
        {:ok, {name, value}} when is_list(value) ->
          {Map.put(ok_set, name, to_string(value)), err_set}
        {:ok, {name, value}} ->
          {Map.put(ok_set, name, value), err_set}
        {:error, reason, id} ->
          {ok_set, [{reason, id} | err_set]}
      end
    end)
  end

  def get_object_attributes(%SessionHandle{} = session, %ObjectHandle{} = object, attribute_set) do
    attribute_names = MapSet.to_list(attribute_set)
    all_atoms = Enum.all?(attribute_names, fn name -> is_atom(name) end)
    if all_atoms do
      res = n_get_object_attributes(session.module.ref, session.handle, object.handle, attribute_names)
      case res do
        {:ok, lst} ->
          {ok_set, fail_list} = split_attributes(lst)
          {:ok, post_convert_attributes(ok_set), fail_list}
        error -> error
      end
    else
      {:error, :invalid_attribute_names}
    end
  end

  @doc """
  Encrypt data using the specified `mechanism` and `key` in a single call. Consider
  using `P11ex.Lib.encrypt_init/3`, `P11ex.Lib.encrypt_update/2`, and
  `P11ex.Lib.encrypt_final/1` if you want to encrypt data in chunks.

  See `P11ex.Lib.encrypt_init/3` for examples on how to select an encryption mechanism
  and set its parameters.
  """
  def encrypt(%SessionHandle{} = session, mechanism, %ObjectHandle{} = key, data)
      when is_binary(data) do
    with :ok <- n_encrypt_init(session.module.ref, session.handle, mechanism, key.handle) do
      n_encrypt(session.module.ref, session.handle, data)
    end
  end

  @doc """
  Initialize an encryption operation involving the specified `mechanism` and `key`. This puts
  the session into encryption mode and no other operations can be active at the same time. Use
  `encrypt_update/2` and `encrypt_final/1` to provide data to encrypt and produce the ciphertext
  chunks. Consider using `encrypt/4` if you want to encrypt data in a single call.

  ## Setting an encryption mechanism

  Some mechanisms require additional parameters. These parameters are passed as a
  map. The NIF will translate the map into the appropriate PKCS#11 mechanism structure.
  If this translation fails (e.g. missing required parameters or wrong type) the operation
  will return an error of the form `{:error, :invalid_parameter, reason}`.

  The following example show how to do this for common mechanisms:

  ### AES ECB

  No additional parameters are required for AES ECB mode.

  ```elixir
  :ok = P11ex.Session.encrypt_init(session, {:ckm_aes_ecb}, key)
  ```

  ### AES CBC and AES OFB

  These mechanisms require an initialization vector (IV). This IV has to be the same length
  as the block size of the cipher. For AES the block size is 16 bytes and thus the IV
  has to be 16 bytes long.

  ```elixir
  iv = :crypto.strong_rand_bytes(16)
  :ok = P11ex.Session.encrypt_init(session1, {:ckm_aes_cbc, %{iv: iv}}, key)
  :ok = P11ex.Session.encrypt_init(session2, {:ckm_aes_ofb, %{iv: iv}}, key)
  ```

  ### AES CTR

  This mechanism requires an initialization vector (IV) and the number of bits in the counter
  (e.g. 32, 64, 128).

  ```elixir
  iv = :crypto.strong_rand_bytes(16)
  params = %{iv: iv, counter_bits: 32}
  :ok = P11ex.Session.encrypt_init(session, {:ckm_aes_ctr, params}, key)
  ```

  ### AES GCM

  This mechanism has the following additional parameters:
  * `:iv` - the initialization vector (IV). Typically, this is 12 bytes long.
  * `:aad` - the optional authentication data (AAD). Not all PKCS#11 tokens support this parameter.
    Also, the size of the AAD is limited by the token.
  * `:tag_bits` - the number of bits in the authentication tag (typically 128)

  ```elixir
  iv = :crypto.strong_rand_bytes(12)
  params = %{iv: iv, tag_bits: 128}
  :ok = P11ex.Session.encrypt_init(session, {:ckm_aes_gcm, params}, key)
  ```

  ### RSA with PKCS#1 v1.5

  This mechanism requires a RSA public key and does not require any additional parameters.

  ```elixir
  :ok = P11ex.Session.encrypt_init(session, {:ckm_rsa_pkcs}, pub_key)
  {:ok, ciphertext} = P11ex.Session.encrypt(session, data)
  ```

  ### RSA OAEP

  This mechanism requires a RSA public key and the following parameters:

  - `:hash_alg` - the hash algorithm to use.
  - `:mgf_hash_alg` - the hash algorithm to use for the mask generation function.
  - `:source_data` - the source data to use for the OAEP padding.

  The `hash_alg` and `mgf_hash_alg` parameters identify an hash algorithm in the
  same way as the `:crypto` module does. That is, possible values are `:sha`,
  `:sha224`, `:sha256`, `:sha384`, and `:sha512`. Support depends on the token.

  Example:

  ```elixir
  :ok = P11ex.Session.encrypt_init(session, {:ckm_rsa_pkcs_oaep, %{hash_alg: :sha, mgf_hash_alg: :sha, source_data: source_data}}, pub_key)
  {:ok, ciphertext} = P11ex.Session.encrypt(session, data)
  ```

  """
  @spec encrypt_init(SessionHandle.t(), mechanism_instance(), ObjectHandle.t())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def encrypt_init(%SessionHandle{} = session, mechanism, %ObjectHandle{} = key) do
    n_encrypt_init(session.module.ref, session.handle, mechanism, key.handle)
  end

  @doc """
  Provide a chunk of plaintext data to the encryption operation that is in
  progress for this session (see `P11ex.Lib.encrypt_init/3`).
  """
  @spec encrypt_update(SessionHandle.t(), binary())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def encrypt_update(%SessionHandle{} = session, data) do
    n_encrypt_update(session.module.ref, session.handle, data)
  end

  @doc """
  Finalize the encryption operation that is in progress for this session.
  """
  @spec encrypt_final(SessionHandle.t())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def encrypt_final(%SessionHandle{} = session) do
    n_encrypt_final(session.module.ref, session.handle)
  end

  @doc """
  Decrypt data using the specified `mechanism` and `key` in a single call. See
  `P11ex.Lib.encrypt_init/3` on how to select a decryption mechanism and
  set its parameters. Consider using `P11ex.Lib.decrypt_init/3`,
  `P11ex.Lib.decrypt_update/2`, and `P11ex.Lib.decrypt_final/1` if you
  want to decrypt data in chunks.
  """
  def decrypt(%SessionHandle{} = session, mechanism, %ObjectHandle{} = key, data) do
    with :ok <- decrypt_init(session, mechanism, key) do
      n_decrypt(session.module.ref, session.handle, data)
    end
  end

  @doc """
  Initialize a decryption operation involving the specified `mechanism` and `key`.
  Many mechanisms require additional parameters. See `P11ex.Lib.encrypt_init/3` for more
  information on mechanisms and their parameters.

  The function returns `:ok` if the operation is initialized successfully. The session
  is now in decryption mode and no other operations can be active at the same time. The
  ciphertext can be provided in chunks using `P11ex.Lib.decrypt_update/2` and
  `P11ex.Lib.decrypt_final/1`.
  """
  @spec decrypt_init(SessionHandle.t(), mechanism_instance(), ObjectHandle.t())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def decrypt_init(%SessionHandle{} = session, mechanism, %ObjectHandle{} = key) do
    n_decrypt_init(session.module.ref, session.handle, mechanism, key.handle)
  end

  @doc """
  Provide a chunk of ciphertext data to the decryption operation that is in
  progress for this session (see `P11ex.Lib.decrypt_init/3`).
  """
  @spec decrypt_update(SessionHandle.t(), binary())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def decrypt_update(%SessionHandle{} = session, data) do
    n_decrypt_update(session.module.ref, session.handle, data)
  end

  @doc """
  Finalize the decryption operation that is in progress for this session
  (see `P11ex.Lib.decrypt_init/3`).
  """
  @spec decrypt_final(SessionHandle.t())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def decrypt_final(%SessionHandle{} = session) do
    n_decrypt_final(session.module.ref, session.handle)
  end

  @doc """
  Generate random data using the token's RNG.
  """
  @spec generate_random(SessionHandle.t(), non_neg_integer())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def generate_random(%SessionHandle{} = session, len)
      when is_integer(len) and len > 0 do
    n_generate_random(session.module.ref, session.handle, len)
  end

  @doc """
  Initialize a signing operation or MAC computation. The `key`'s type
  must be suitable for the specified `mechanism`. If the initialization
  is successful, the session's current operation is set to `:sign`. This
  operation can be finalized by calling `sign_final/1` or `sign/2`. Use
  `sign_update/2` to provide data to the signing operation.

  ## Example: Signing data in chunks

  ```elixir
  :ok = Session.sign_init(session, {:ckm_rsa_pkcs, %{hash_alg: :sha256}}, priv_key)
  :ok = Session.sign_update(session, data1)
  :ok = Session.sign_update(session, data2)
  {:ok, signature} = Session.sign_final(session)
  ```

  ## Example: Signing data in one go

  ```elixir
  :ok = Session.sign_init(session, {:ckm_rsa_pkcs, %{hash_alg: :sha256}}, priv_key)
  {:ok, signature} = Session.sign(session, data)
  ```

  ## Signing Mechanisms

  ### RSA PKCS #1 v1.5 Signature and Encryption Mechanism

  This mechanism requires a RSA private key and does not require any
  additional parameters. The digest algorithm to use is specified in the
  mechanism name. The following mechanisms fall into this category:

  - `:ckm_rsa_pkcs` (uses plain RSA PKCS#1 v1.5 without digest computation)
  - `:ckm_sha1_rsa_pkcs`
  - `:ckm_sha224_rsa_pkcs`
  - `:ckm_sha256_rsa_pkcs`
  - `:ckm_sha384_rsa_pkcs`
  - `:ckm_sha512_rsa_pkcs`

  Example:

  ```elixir
  :ok = Session.sign_init(session, {:ckm_sha256_rsa_pkcs}, priv_key)
  {:ok, signature} = Session.sign(session, data)
  ```

  ### RSA PKCS #1 PSS Signature Mechanism (`:ckm_rsa_pkcs_pss`)

  This mechanism requires a RSA private key and the following parameters:

  - `:salt_len` - the length of the salt in bytes.
  - `:hash_alg` - the hash algorithm to use.
  - `:mgf_hash_alg` - the hash algorithm to use for the mask generation function.

  The `hash_alg` and `mgf_hash_alg` parameters identify an hash algorithm in the
  same way as the `:crypto` module does. That is, possible values are `:sha`,
  `:sha224`, `:sha256`, `:sha384`, and `:sha512`.

  Example:

  ```elixir
  :ok = Session.sign_init(session, {:ckm_rsa_pkcs_pss, %{salt_len: 20, hash_alg: :sha256, mgf_hash_alg: :sha256}}, priv_key)
  {:ok, signature} = Session.sign(session, data)
  ```

  ### ECDSA Signature Mechanism (`:ckm_ecdsa`)

  This algorithm requires a pre-computed digest of the data to sign. That is,
  it does not compute the digest itself.

  Example:

  ```elixir
  data = :crypto.strong_rand_bytes(1024)
  digest = :crypto.hash(:sha256, data)

  :ok = Session.sign_init(session, {:ckm_ecdsa}, priv_key)
  {:ok, signature} = Session.sign(session, digest)
  ```
  """
  @spec sign_init(SessionHandle.t(), mechanism_instance(), ObjectHandle.t())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def sign_init(%SessionHandle{} = session, mechanism, %ObjectHandle{} = key)
      when is_tuple(mechanism) do
    n_sign_init(session.module.ref, session.handle, mechanism, key.handle)
  end

  @doc """
  Provide data to the signing operation or MAC computation. The session must
  be in the `:sign` state, so this function must be called after `sign_init/3`.
  Call this function repeatedly with chunks of data until all data has been
  provided. If the operation fails, the session's current operation is reset.
  """
  @spec sign_update(SessionHandle.t(), binary())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def sign_update(%SessionHandle{} = session, data)
      when is_binary(data) do
    n_sign_update(session.module.ref, session.handle, data)
  end

  @doc """
  Finalize the signing operation or MAC computation. The session must
  be in the `:sign` state, so this function must be called after
  `sign_init/3` and `sign_update/2`. If the operation fails, the session's
  current operation is reset. The function returns the signature or MAC.
  """
  @spec sign_final(SessionHandle.t())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def sign_final(%SessionHandle{} = session) do
    n_sign_final(session.module.ref, session.handle)
  end

  @doc """
  Sign or MAC data. The session must be in the `:sign` state, so this function
  must be called after `sign_init/3`. If the operation
  fails, the session's current operation is reset. The function returns the
  signature or MAC.
  """
  @spec sign(SessionHandle.t(), binary())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def sign(%SessionHandle{} = session, data)
      when is_binary(data) do
    n_sign(session.module.ref, session.handle, data)
  end

  @doc """
  Initialize a verification operation involving the specified `mechanism` and `key`.
  The operation verifies signatures or MACs, depending the mechanism. Some mechanisms
  require additional parameters. See `P11ex.Lib.sign_init/3` for more information
  on mechanisms and their parameters.

  If successful, the session is in verification mode and no other operations can be
  active at the same time.

  ## Example: Verifying a RSA PKCS #1 v1.5 signature

  ```elixir
  :ok = Session.verify_init(session, {:ckm_sha256_rsa_pkcs}, pub_key)
  :ok = Session.verify(session, data, signature)
  ```
  """
  @spec verify_init(SessionHandle.t(), mechanism_instance(), ObjectHandle.t())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def verify_init(%SessionHandle{} = session, mechanism, %ObjectHandle{} = key)
        when is_tuple(mechanism) do
    n_verify_init(session.module.ref, session.handle, mechanism, key.handle)
  end

  @doc """
  Verify a signature or MAC. The session must be in the `:verify` state, so this function
  must be called after `verify_init/3`. If the operation fails, the session's current
  operation is reset.

  The operation return `:ok` if the signature (or MAC) is valid. Otherwise, it returns
  an error. Typically, the error reason is `:ckr_signature_invalid` or `:ckr_signature_len_range`.
  """
  @spec verify(SessionHandle.t(), binary(), binary())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def verify(%SessionHandle{} = session, data, signature)
      when is_binary(data) and is_binary(signature) do
    n_verify(session.module.ref, session.handle, data, signature)
  end

  @doc """
  Initialize a digest operation. The session's current operation is set to
  `:digest`. Use `digest_update/2` to provide data to the digest operation.
  Call `digest_final/1` to finalize the operation and get the digest. Or, call
  `digest/2` to provide all data at once and get the digest in one go.

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
  @spec digest_init(SessionHandle.t(), mechanism_instance())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def digest_init(%SessionHandle{} = session, mechanism)
      when is_tuple(mechanism) do
    n_digest_init(session.module.ref, session.handle, mechanism)
  end

  @doc """
  Provide data to the digest operation. The session must be in the `:digest`
  state, so this function must be called after `digest_init/2`. Call this
  function repeatedly with chunks of data until all data has been provided.
  If the operation fails, the session's current operation is reset.
  """
  @spec digest_update(SessionHandle.t(), binary())
    :: :ok | {:error, atom()} | {:error, atom(), any()}
  def digest_update(%SessionHandle{} = session, data)
      when is_binary(data) do
    n_digest_update(session.module.ref, session.handle, data)
  end

  @doc """
  Finalize the digest operation. The session must be in the `:digest` state,
  so this function must be called after `digest_init/2` and `digest_update/2`.
  If the operation fails, the session's current operation is reset. The function
  returns the digest.
  """
  @spec digest_final(SessionHandle.t())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def digest_final(%SessionHandle{} = session) do
    n_digest_final(session.module.ref, session.handle)
  end

  @doc """
  Get the digest of the data provided to the digest operation. The session must
  be in the `:digest` state, so this function must be called after `digest_init/2`.
  Use `digest/2` to provide all data at once and get the digest in one go.
  """
  @spec digest(SessionHandle.t(), binary())
    :: {:ok, binary()} | {:error, atom()} | {:error, atom(), any()}
  def digest(%SessionHandle{} = session, data)
      when is_binary(data) do
    n_digest(session.module.ref, session.handle, data)
  end

  def destroy_object(%SessionHandle{} = session, %ObjectHandle{} = object) do
    n_destroy_object(session.module.ref, session.handle, object.handle)
  end

  def list_mechanisms(%ModuleHandle{} = module, slot_id)
      when is_integer(slot_id) and slot_id >= 0 do
    n_list_mechanisms(module.ref, slot_id)
  end

  def mechanism_info(%ModuleHandle{} = module, slot_id, mechanism_type)
      when ((is_integer(mechanism_type) and mechanism_type >= 0) or is_atom(mechanism_type))
           and is_integer(slot_id) and slot_id >= 0 do
    with {:ok, {min_length, max_length, flags}} <- n_mechanism_info(module.ref, slot_id, mechanism_type) do
      {:ok, %{
        min_length: min_length,
        max_length: max_length,
        flags: P11ex.Flags.to_atoms(:mechanism, flags)
      }}
    end
  end

  @doc """
  Generate a key pair in the session. The key pair is generated according to the specified `mechanism`
  and the `pub_key_template` and `priv_key_template`. The function returns a tuple with the public
  and private key handles.

  ## Example: Generate a RSA key pair

  ```elixir
  mechanism = {:ckm_rsa_pkcs_key_pair_gen}

  pubk_template = [
    {:cka_token, false},
    {:cka_encrypt, true},
    {:cka_verify, true},
    {:cka_modulus_bits, 2048},
    {:cka_public_exponent, 65537},
    {:cka_label, "rsa_test_key"}
  ]

  prvk_template = [
    {:cka_token, false},
    {:cka_private, true},
    {:cka_sensitive, true},
    {:cka_decrypt, true},
    {:cka_sign, true},
    {:cka_label, "rsa_test_key"}
  ]

  {pubk, prvk} =
    P11ex.Session.generate_key_pair(session_pid,
    {:ckm_rsa_pkcs_key_pair_gen},
    pubk_template, prvk_template)
  ```

  ## Example: Generate an EC key pair (secp256r1)

  See `P11ex.ECParam.ec_params_from_named_curve/1` for more functions that
  help to create the value of the `:cka_ec_params` attribute.

  ```elixir
  key_id = :crypto.strong_rand_bytes(16)

  mechanism = {:ckm_ec_key_pair_gen}
  {:ok, params} = ECParam.ec_params_from_named_curve(:secp256r1)

  pubk_template = [
    {:cka_token, false},
    {:cka_key_type, :ckk_ec},
    {:cka_verify, true},
    {:cka_label, "pubk-secp256r1"},
    {:cka_ec_params, params},
    {:cka_id, key_id}
  ]

  prvk_template = [
    {:cka_token, false},
    {:cka_key_type, :ckk_ec},
    {:cka_sign, true},
    {:cka_label, "prvk-secp256r1"},
    {:cka_id, key_id}
  ]

  {:ok, {pubk, prvk}} =
      Session.generate_key_pair(context.session_pid,
          mechanism, pubk_template, prvk_template)
  ```
  """
  @spec generate_key_pair(SessionHandle.t(), mechanism_instance(), attributes(), attributes())
    :: {:ok, {ObjectHandle.t(), ObjectHandle.t()}} | {:error, atom()} | {:error, atom(), any()}
  def generate_key_pair(session, mechanism, pub_key_template, priv_key_template) do
    with {:ok, pubk_attribs} <- process_attributes(pub_key_template),
         {:ok, prvk_attribs} <- process_attributes(priv_key_template) do
      case n_generate_key_pair(session.module.ref, session.handle,
                               mechanism, pubk_attribs, prvk_attribs) do
        {:ok, {pubk_handle, prvk_handle}} ->
          {:ok, {ObjectHandle.new(session, pubk_handle), ObjectHandle.new(session, prvk_handle)}}
        error -> error
      end
    end
  end

  #   _   _      _                   _____                 _   _
  #  | | | | ___| |_ __   ___ _ __  |  ___|   _ _ __   ___| |_(_) ___  _ __  ___
  #  | |_| |/ _ \ | '_ \ / _ \ '__| | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
  #  |  _  |  __/ | |_) |  __/ |    |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
  #  |_| |_|\___|_| .__/ \___|_|    |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
  #               |_|

  # Fixed length strings in PKCS#11 are padded with blanks. Remove the
  # trailing blanks.
  defp frob_fixedlen_string(char_list) when is_list(char_list) do
    char_list |> List.to_string() |> String.trim_trailing()
  end

  defp frob_utc_date_str(char_list) when is_list(char_list) do
    case String.trim(List.to_string(char_list)) do
      "" -> nil
      s -> s
    end
  end

  #    _   _ ___ _____   _____                 _   _
  #   | \ | |_ _|  ___| |  ___|   _ _ __   ___| |_(_) ___  _ __  ___
  #   |  \| || || |_    | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
  #   | |\  || ||  _|   |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
  #   |_| \_|___|_|     |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/

  defp n_load_module(_path) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF load_module/1 not implemented")
  end

  defp n_list_slots(_p11_module, _token_present) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF list_slots/1 not implemented")
  end

  defp n_token_info(_p11_module, _slot_id) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF token_info/1 not implemented")
  end

  defp n_finalize(_p11_module) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF finalize/1 not implemented")
  end

  defp n_open_session(_p11_module, _slot_id, _flags) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF open_session/3 not implemented")
  end

  defp n_close_session(_p11_module, _session) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF close_session/1 not implemented")
  end

  defp n_close_all_sessions(_p11_module, _slot_id) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF close_all_sessions/1 not implemented")
  end

  defp n_session_info(_p11_module, _session) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF session_info/1 not implemented")
  end

  defp n_session_login(_p11_module, _session, _user_type, _pin) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF session_login/4 not implemented")
  end

  defp n_session_logout(_p11_module, _session) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF session_logout/1 not implemented")
  end

  defp n_find_objects(_p11_module, _session, _mechanism, _key_template) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF find_objects/4 not implemented")
  end

  defp n_generate_key(_p11_module, _session, _mechanism, _key_template) do
    # This function will be implemented in NIF
    #raise "NIF generate_key/4 not implemented"
    :erlang.nif_error("NIF generate_key/4 not implemented")
  end

  defp n_destroy_object(_p11_module, _session, _object) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF destroy_object/3 not implemented")
  end

  defp n_list_mechanisms(_p11_module, _slot_id) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF list_mechanisms/2 not implemented")
  end

  defp n_mechanism_info(_p11_module, _slot_id, _mechanism_type) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF mechanism_info/3 not implemented")
  end

  defp n_get_object_attributes(_p11_module, _session, _object, _attributes) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF get_object_attributes/4 not implemented")
  end

  defp n_encrypt(_p11_module, _session, _data) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF encrypt/3 not implemented")
  end

  defp n_encrypt_init(_p11_module, _session, _mechanism, _data) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF encrypt_init/4 not implemented")
  end

  defp n_encrypt_update(_p11_module, _session, _data) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF encrypt_update/3 not implemented")
  end

  defp n_encrypt_final(_p11_module, _session) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF encrypt_final/2 not implemented")
  end

  defp n_decrypt(_p11_module, _session, _data) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF decrypt/3 not implemented")
  end

  defp n_decrypt_init(_p11_module, _session, _mechanism, _data) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF decrypt_init/4 not implemented")
  end

  defp n_decrypt_update(_p11_module, _session, _data) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF decrypt_update/3 not implemented")
  end

  defp n_decrypt_final(_p11_module, _session) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF decrypt_final/2 not implemented")
  end

  defp n_generate_random(_p11_module, _session, _requested_length) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF generate_random/3 not implemented")
  end

  defp n_sign_init(_p11_module, _session, _mechanism, _key) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF sign_init/4 not implemented")
  end

  defp n_sign(_p11_module, _session, _data) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF sign/5 not implemented")
  end

  defp n_sign_update(_p11_module, _session, _data) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF sign_update/3 not implemented")
  end

  defp n_sign_final(_p11_module, _session) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF sign_final/2 not implemented")
  end

  defp n_verify_init(_p11_module, _session, _mechanism, _key) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF verify_init/4 not implemented")
  end

  defp n_verify(_p11_module, _session, _data, _signature) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF verify/4 not implemented")
  end

  defp n_digest_init(_p11_module, _session, _mechanism) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF digest_init/3 not implemented")
  end

  defp n_digest_update(_p11_module, _session, _data) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF digest_update/3 not implemented")
  end

  defp n_digest_final(_p11_module, _session) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF digest_final/2 not implemented")
  end

  defp n_digest(_p11_module, _session, _data) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF digest/2 not implemented")
  end

  defp n_generate_key_pair(_p11_module, _session, _mechanism,
    _pub_key_template, _priv_key_template) do
    # This function will be implemented in NIF
    :erlang.nif_error("NIF generate_key_pair/5 not implemented")
  end

end
