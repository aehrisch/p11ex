defmodule P11ex.ECSignTest do
  use ExUnit.Case

  alias P11ex.Session, as: Session

  @moduletag :ec
  @moduletag :ec_sign
  @moduletag :softhsm

  setup_all do
    {:ok, context} = P11ex.TestHelper.setup_session()
    {pubk, prvk} = ECSignTestHelper.gen_keypair(context.session_pid, :secp521r1)
    context = Map.merge(context, %{curve: :secp521r1, pubk: pubk, prvk: prvk})
    {:ok, context}
  end

  test "sign and verify EC signature", %{pubk: pubk, prvk: prvk} = context do

    data = :crypto.strong_rand_bytes(1024)
    digest = :crypto.hash(:sha256, data)

    :ok = Session.sign_init(context.session_pid, {:ckm_ecdsa}, prvk)
    {:ok, signature} = Session.sign(context.session_pid, digest)

    assert :ok = Session.verify_init(context.session_pid, {:ckm_ecdsa}, pubk)
    assert :ok = Session.verify(context.session_pid, digest, signature)
  end

end
