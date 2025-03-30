defmodule P11ExTest.DigestTest do

  use ExUnit.Case, async: false

  alias P11ex.Lib, as: Lib
  alias P11ex.Module, as: Module
  alias P11ex.Session, as: Session

  @moduletag :digest

  setup_all do
    P11ex.TestHelper.setup_session()
  end

  test "SHA digest, one call", context do

    test_data = :crypto.strong_rand_bytes(1024)

    algs = [
      {:ckm_sha1, 20, :sha},
      {:ckm_sha224, 28, :sha224},
      {:ckm_sha256, 32, :sha256},
      {:ckm_sha384, 48, :sha384},
      {:ckm_sha512, 64, :sha512}
    ]

    algs
      |> Enum.each(fn {mechanism, size, name} ->

        :ok = Session.digest_init(context.session_pid, {mechanism})
        {:ok, digest} = Session.digest(context.session_pid, test_data)

        assert digest != nil
        assert is_binary(digest)
        assert byte_size(digest) == size
        assert :crypto.hash(name, test_data) == digest
    end)
  end

end
