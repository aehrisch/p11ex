defmodule P11ex.YubikeyDigestTest do

  use ExUnit.Case, async: false

  alias P11ex.Session, as: Session

  @moduletag :digest
  @moduletag :yubikey

  setup_all do
    {:ok, context} = YubikeyTestHelper.setup_session()
    {:ok, context}
  end

  test "YubiKey, compute digest", %{session_pid: session_pid} = context do

    {:ok, random} = Session.generate_random(session_pid, 16)
    assert is_binary(random)
    assert byte_size(random) == 16

    algs = [
      {:ckm_sha1, 20, :sha},
      {:ckm_sha256, 32, :sha256},
      {:ckm_sha384, 48, :sha384},
      {:ckm_sha512, 64, :sha512}
    ]

    algs |> Enum.each(fn {mechanism, size, name} ->
      :ok = Session.digest_init(session_pid, {mechanism})
      {:ok, digest} = Session.digest(session_pid, random)

      assert digest != nil
      assert is_binary(digest)
      assert byte_size(digest) == size
      assert :crypto.hash(name, random) == digest
    end)
  end

end
