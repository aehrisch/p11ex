defmodule P11exBench.Controllers.Aes do
  alias P11ex.Session, as: Session
  alias P11ex.Lib, as: Lib
  alias P11ex.Module, as: Module

  def generate_token_key(label, key_size) do
    :poolboy.transaction(P11exBench.SessionPool, fn session ->

      template = [
        {:cka_token, true},
        {:cka_label, label},
        {:cka_value_len, key_size},
        {:cka_id, :crypto.strong_rand_bytes(key_size)}
      ]

      with :ok <- Session.login(session, :user, "1234"),
           {:ok, key} <- Session.generate_key(session, {:ckm_aes_key_gen}, template),
           {:ok, attribs, []} <- Session.read_object(session, key, Lib.ObjectAttributes.secret_key) do
        {:ok, %{key_handle: key.handle, cka_id: Base.encode16(attribs.cka_id), cka_label: attribs.cka_label}}
      end

    end)
  end

  def encrypt(key_handle, plaintext) do
    :poolboy.transaction(P11exBench.SessionPool, fn session ->

      iv = :crypto.strong_rand_bytes(12)
      IO.inspect(session, label: "session")
      IO.inspect(key_handle, label: "key_handle")

      handle = Lib.ObjectHandle.new(key_handle)
      Session.encrypt(session, {:ckm_aes_gcm, %{iv: iv, tag_bits: 128}}, handle, plaintext)
    end)
  end

  def encrypt_chunks(key_handle, plaintext) do
    :poolboy.transaction(P11exBench.SessionPool, fn session ->
      iv = :crypto.strong_rand_bytes(12)
      handle = Lib.ObjectHandle.new(key_handle)
      Session.encrypt_init(session, {:ckm_aes_gcm, %{iv: iv, tag_bits: 128}}, handle)

      # Split plaintext into chunks
      chunks = for <<chunk::binary-size(8192) <- plaintext>>, do: chunk

      # Process each chunk
      results = Enum.map(chunks, fn chunk ->
        {:ok, data} = Session.encrypt_update(session, chunk)
        data
      end)

      # Get the final result
      {:ok, final_result} = Session.encrypt_final(session)

      {:ok, Enum.join(results ++ [final_result])}
    end)
  end

end
