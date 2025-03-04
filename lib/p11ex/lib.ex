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

    @enforce_keys [:module, :slot_id, :description, :manufacturer_id, :hardware_version, :firmware_version, :flags]
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
    Represents a PKCS#11 object. An object stored in the token. This can be a key,
    a certificate, a secret key, etc.
    """

    @typedoc """
    The PKCS#11 session that the object belongs to.
    """
    @type session :: P11ex.Lib.SessionHandle.t()

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
    Create a new object handle.
    """
    @spec new(session(), handle()) :: t()
    def new(%SessionHandle{} = session, handle)
        when is_integer(handle) and handle >= 0 do
      %__MODULE__{session: session, handle: handle}
    end

    def new(_, _) do
      raise ArgumentError, "handle must be a number"
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
    def common(), do: MapSet.new([:cka_class])

    @doc """
    Attributes related to the storage of objects. Most objects have these attributes.
    """
    @spec storage() :: MapSet.t(atom())
    def storage(), do: MapSet.union(common(),
        MapSet.new([:cka_label, :cka_modifiable, :cka_private, :cka_token]))


    @doc """
    Attributes related to keys. This are attributes can be found on secrets keys,
    public keys, and private keys.
    """
    @spec key() :: MapSet.t(atom())
    def key() do
      MapSet.union(storage(),
        MapSet.new([:cka_derive, :cka_end_date, :cka_id,
                    :cka_id, :cka_key_gen_mechanism, :cka_key_type,
                    :cka_local, :cka_start_date]))
    end

    @doc """
    Attributes that can be found on secret keys.
    """
    @spec secret_key() :: MapSet.t(atom())
    def secret_key() do
      MapSet.union(key(),
        MapSet.new([:cka_always_sensitive, :cka_check_value,
          :cka_decrypt, :cka_encrypt,
          :cka_extractable, :cka_never_extractable,
          :cka_sign, :cka_trusted,
          :cka_unwrap, :cka_verify,
          :cka_wrap, :cka_wrap_with_trusted,
          :cka_value_len]))
    end

  end

  @on_load :load_nifs

  def load_nifs do
    # Path to the compiled NIF library
    Logger.info("Loading NIF p11ex_nif")
    path = :filename.join(:code.priv_dir(:p11ex), "p11ex_nif")
    :erlang.load_nif(path, 0)
  end

  @spec load_module(String.t()) :: {:ok, Module.t()} | {:error, String.t()}
  def load_module(path) do
    Logger.info("Loading PKCS#11 module: #{path}")
    with {:ok, ref} <- n_load_module(String.to_charlist(path)) do
      Logger.debug("n_load_module returned ref=#{inspect(ref)}")
      {:ok, %ModuleHandle{path: path, ref: ref}}
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

  def session_login(%SessionHandle{} = session, user_type, pin)
      when is_atom(user_type) and is_binary(pin) do
    user_type_flag = P11ex.Flags.from_atoms(:user_type, MapSet.new([user_type]))
    Logger.info("logging in to session #{inspect(session)} as #{user_type}")
    n_session_login(session.module.ref, session.handle,
                    user_type_flag, String.to_charlist(pin))
  end

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

  defp process_attributes(attributes) when is_list(attributes) do
    if Enum.all?(attributes, fn
          {key, _value} when is_atom(key) -> true
           _ -> false
       end) do
#        updated_tuples = Enum.map(attributes, fn
#          {key, value} when is_binary(value) -> {key, String.to_charlist(value)}
#          {key, value} -> {key, value}
#        end)

        {:ok, attributes}
    else
      {:error, :invalid_attributes_tuples}
    end
  end

  def find_objects(%SessionHandle{} = session, attributes, max_hits)
      when is_list(attributes) and is_integer(max_hits) and max_hits >= 0 do
    with {:ok, attributes} <- process_attributes(attributes),
         {:ok, handles} <- n_find_objects(session.module.ref, session.handle, attributes, max_hits) do
      {:ok, Enum.map(handles, fn handle -> ObjectHandle.new(session, handle) end)}
    end
  end

  def generate_key(%SessionHandle{} = session, mechanism, key_template)
      when is_list(key_template) do
    Logger.debug("generate_key: session=#{inspect(session)}, mechanism=#{inspect(mechanism)}, key_template=#{inspect(key_template)}")
    with {:ok, attributes} <- process_attributes(key_template) do
      n_generate_key(session.module.ref, session.handle, mechanism, attributes)
    end
  end

  def get_object_attributes(%SessionHandle{} = session, %ObjectHandle{} = object, attribute_set) do
    attribute_names = MapSet.to_list(attribute_set)
    all_atoms = Enum.all?(attribute_names, fn name -> is_atom(name) end)
    if not all_atoms do
      {:error, :invalid_attribute_names}
    else
      res = n_get_object_attributes(session.module.ref, session.handle, object.handle, attribute_names)
      case res do
        {:ok, lst} ->
          {ok_set, fail_list} =
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
          {:ok, ok_set, fail_list}
        error -> error
      end
    end
  end

  def encrypt(%SessionHandle{} = session, mechanism, %ObjectHandle{} = key, data)
      when is_binary(data) do
    with :ok <- n_encrypt_init(session.module.ref, session.handle, mechanism, key.handle) do
      n_encrypt(session.module.ref, session.handle, data)
    end
  end

  def encrypt_init(%SessionHandle{} = session, mechanism, %ObjectHandle{} = key) do
    n_encrypt_init(session.module.ref, session.handle, mechanism, key.handle)
  end

  def encrypt_update(%SessionHandle{} = session, data) do
    n_encrypt_update(session.module.ref, session.handle, data)
  end

  def encrypt_final(%SessionHandle{} = session) do
    n_encrypt_final(session.module.ref, session.handle)
  end

  def decrypt(%SessionHandle{} = session, mechanism, %ObjectHandle{} = key, data) do
    with :ok <- decrypt_init(session, mechanism, key) do
      n_decrypt(session.module.ref, session.handle, data)
    end
  end

  def decrypt_init(%SessionHandle{} = session, mechanism, %ObjectHandle{} = key) do
    n_decrypt_init(session.module.ref, session.handle, mechanism, key.handle)
  end

  def decrypt_update(%SessionHandle{} = session, data) do
    n_decrypt_update(session.module.ref, session.handle, data)
  end

  def decrypt_final(%SessionHandle{} = session) do
    n_decrypt_final(session.module.ref, session.handle)
  end

  def generate_random(%SessionHandle{} = session, len)
      when is_integer(len) and len > 0 do
    n_generate_random(session.module.ref, session.handle, len)
  end

  def destroy_object(%SessionHandle{} = session, %ObjectHandle{} = object) do
    n_destroy_object(session.module.ref, session.handle, object.handle)
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

  defp frob_date(char_list) when is_list(char_list) do
    char_list
    |> List.to_string() |> String.trim_trailing()
    |> Date.from_iso8601()
  end

  #    _   _ ___ _____   _____                 _   _
  #   | \ | |_ _|  ___| |  ___|   _ _ __   ___| |_(_) ___  _ __  ___
  #   |  \| || || |_    | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
  #   | |\  || ||  _|   |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
  #   |_| \_|___|_|     |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/

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

  defp n_finalize(_p11_module) do
    # This function will be implemented in NIF
    raise "NIF finalize/1 not implemented"
  end

  defp n_open_session(_p11_module, _slot_id, _flags) do
    # This function will be implemented in NIF
    raise "NIF open_session/1 not implemented"
  end

  defp n_close_session(_p11_module, _session) do
    # This function will be implemented in NIF
    raise "NIF close_session/1 not implemented"
  end

  defp n_close_all_sessions(_p11_module, _slot_id) do
    # This function will be implemented in NIF
    raise "NIF close_all_sessions/1 not implemented"
  end

  defp n_session_info(_p11_module, _session) do
    # This function will be implemented in NIF
    raise "NIF session_info/1 not implemented"
  end

  defp n_session_login(_p11_module, _session, _user_type, _pin) do
    # This function will be implemented in NIF
    raise "NIF session_login/4 not implemented"
  end

  defp n_session_logout(_p11_module, _session) do
    # This function will be implemented in NIF
    raise "NIF session_logout/1 not implemented"
  end

  defp n_find_objects(_p11_module, _session, _mechanism, _key_template) do
    # This function will be implemented in NIF
    raise "NIF find_objects/4 not implemented"
  end

  defp n_generate_key(_p11_module, _session, _mechanism, _key_template) do
    # This function will be implemented in NIF
    raise "NIF generate_key/4 not implemented"
  end

  defp n_destroy_object(_p11_module, _session, _object) do
    # This function will be implemented in NIF
    raise "NIF destroy_object/3 not implemented"
  end

  defp n_get_object_attributes(_p11_module, _session, _object, _attributes) do
    # This function will be implemented in NIF
    raise "NIF get_object_attributes/4 not implemented"
  end

  defp n_encrypt(_p11_module, _session, _data) do
    # This function will be implemented in NIF
    raise "NIF encrypt/3 not implemented"
  end

  defp n_encrypt_init(_p11_module, _session, _mechanism, _data) do
    # This function will be implemented in NIF
    raise "NIF encrypt_init/4 not implemented"
  end

  defp n_encrypt_update(_p11_module, _session, _data) do
    # This function will be implemented in NIF
    raise "NIF encrypt_update/3 not implemented"
  end

  defp n_encrypt_final(_p11_module, _session) do
    # This function will be implemented in NIF
    raise "NIF encrypt_final/2 not implemented"
  end

  defp n_decrypt(_p11_module, _session, _data) do
    # This function will be implemented in NIF
    raise "NIF decrypt/3 not implemented"
  end

  defp n_decrypt_init(_p11_module, _session, _mechanism, _data) do
    # This function will be implemented in NIF
    raise "NIF decrypt_init/4 not implemented"
  end

  defp n_decrypt_update(_p11_module, _session, _data) do
    # This function will be implemented in NIF
    raise "NIF decrypt_update/3 not implemented"
  end

  defp n_decrypt_final(_p11_module, _session) do
    # This function will be implemented in NIF
    raise "NIF decrypt_final/2 not implemented"
  end

  defp n_generate_random(_p11_module, _session, _requested_length) do
    # This function will be implemented in NIF
    raise "NIF generate_random/3 not implemented"
  end

end
