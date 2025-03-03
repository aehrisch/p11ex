defmodule P11ExTest.FindSecretKey do

  use ExUnit.Case, async: false

  alias P11ex.Session, as: Session
  alias P11ex.Module, as: Module
  alias P11ex.Lib, as: Lib
  alias GenServer

  @aes_key_labels ["aes_128", "aes_192", "aes_256"]

  setup_all do
    P11ex.TestHelper.setup_session()
  end


  @tag focus: true
  test "find seck by label", context do

    @aes_key_labels
    |> Enum.each(fn label ->
      attribs = [{:cka_class, :cko_secret_key}, {:cka_label, label}]
      {:ok, objects} = Session.find_objects(context.session_pid, attribs, 5)

      [hit | more] = objects
      assert more == []

      assert is_map(hit)
      assert hit.__struct__ == P11ex.Lib.ObjectHandle
      assert Map.has_key?(hit, :handle)
      assert is_number(hit.handle)
      assert Map.has_key?(hit, :session)
      assert hit.session.__struct__ == P11ex.Lib.SessionHandle
    end)
  end

  test "read common attributes from secret key", context do

    keys = [{"aes_128", 16}, {"aes_192", 24}, {"aes_256", 32}]

    Enum.each(keys, fn {label, key_length} ->

      # search for the secret key object by label
      attribs = [{:cka_class, :cko_secret_key}, {:cka_label, label}]
      {:ok, objects} = Session.find_objects(context.session_pid, attribs, 3)

      # one hit expected (we assume the label is unique)
      [hit | more] = objects
      assert more == []

      assert is_map(hit)
      assert hit.__struct__ == P11ex.Lib.ObjectHandle

      # read the attributes that are common for all key types
      {:ok, attributes, failed} = Session.read_object(context.session_pid, hit, :cko_key)
      assert failed == []

      assert is_map(attributes)

      assert Map.has_key?(attributes, :cka_class)
      assert attributes.cka_class == :cko_secret_key

      assert Map.has_key?(attributes, :cka_key_type)
      assert attributes.cka_key_type == :ckk_aes

      assert Map.has_key?(attributes, :cka_label)
      assert attributes.cka_label == label

      assert Map.has_key?(attributes, :cka_token)
      assert attributes.cka_token == true

      # false because it's a secret key and not a private key
      assert Map.has_key?(attributes, :cka_private)
      assert attributes.cka_private == false

      assert Map.has_key?(attributes, :cka_derive)
      assert attributes.cka_derive == false

      assert Map.has_key?(attributes, :cka_local)
      assert attributes.cka_local == true

      assert Map.has_key?(attributes, :cka_start_date)
      assert attributes.cka_start_date == :inaccessible
    end)
  end

  @tag focus: true
  test "read typical attributes from secret key", context do

      keys = [{"aes_128", 16}, {"aes_192", 24}, {"aes_256", 32}]

      Enum.each(keys, fn {label, key_length} ->

      # search for the secret key object by label
      attribs = [{:cka_class, :cko_secret_key}, {:cka_label, label}]
      {:ok, objects} = Session.find_objects(context.session_pid, attribs, 3)

      # one hit expected (we assume the label is unique)
      [hit | more] = objects
      assert more == []

      assert is_map(hit)
      assert hit.__struct__ == P11ex.Lib.ObjectHandle

      # read the attributes that are typical for secret keys
      {:ok, attributes, failed} = Session.read_object(context.session_pid, hit, :cko_secret_key)
      assert failed == []

      assert is_map(attributes)

      assert Map.has_key?(attributes, :cka_class)
      assert attributes.cka_class == :cko_secret_key

      assert Map.has_key?(attributes, :cka_label)
      assert attributes.cka_label == label

      assert Map.has_key?(attributes, :cka_key_type)
      assert attributes.cka_key_type == :ckk_aes

      assert Map.has_key?(attributes, :cka_token)
      assert attributes.cka_token == true

      assert Map.has_key?(attributes, :cka_private)
      assert attributes.cka_private == false

      assert Map.has_key?(attributes, :cka_derive)
      assert attributes.cka_derive == false

      assert Map.has_key?(attributes, :cka_local)
      assert attributes.cka_local == true

      assert Map.has_key?(attributes, :cka_start_date)
      assert attributes.cka_start_date == :inaccessible

      assert Map.has_key?(attributes, :cka_end_date)
      assert attributes.cka_end_date == :inaccessible

      assert Map.has_key?(attributes, :cka_id)
      assert is_binary(attributes.cka_id)

      assert Map.has_key?(attributes, :cka_key_gen_mechanism)
      assert attributes.cka_key_gen_mechanism == :ckm_aes_key_gen

      assert Map.has_key?(attributes, :cka_value_len)
      assert attributes.cka_value_len == key_length
    end)
  end

end
