defmodule P11ex.SupervisionTest do

  use ExUnit.Case, async: false

  @registry P11ex.SupervisionTest.Registry
  @supervisor P11ex.SupervisionTest.Supervisor

  setup do
    [
      {Registry, name: @registry, keys: :unique},
      {DynamicSupervisor, name: @supervisor, strategy: :one_for_one, max_restarts: 0},
    ]
    |> Supervisor.start_link(strategy: :one_for_one)

    :ok
  end

  @moduletag :supervision

  # This test starts an alternate module as the child of a supervisor,
  # and is able to start the module a second time once the the supervisor
  # terminates the first child.
  test "starts and stops an alternate module" do
    module_path = System.get_env("ALTERNATE_MODULE", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")
    args1 = [module_path, name: {:via, Registry, {@registry, {:module, 1}}}]
    args2 = [module_path, name: {:via, Registry, {@registry, {:module, 2}}}]

    assert {:ok, pid1} = DynamicSupervisor.start_child(@supervisor, {P11ex.Module, args1})
    assert DynamicSupervisor.start_child(@supervisor, {P11ex.Module, args2}) ==
      {:error, {:C_Initialize, :ckr_cryptoki_already_initialized}}

    assert DynamicSupervisor.terminate_child(@supervisor, pid1) == :ok
    assert {:ok, pid2} = DynamicSupervisor.start_child(@supervisor, {P11ex.Module, args2})
    assert DynamicSupervisor.terminate_child(@supervisor, pid2) == :ok
  end

  # This test starts two sessions as the children of a supervisor.
  # It logs into the first session, then terminates the first child
  # and verifies that the first session has been closed.
  #
  # It then checks that the second session is still alive and is logged in --
  # and that the Module.login_type/0 tracking has tracked this correctly;
  # then terminates the second child and verifies the second session has been closed.
  #
  # Finally, it starts a third child session, verifies that the new session
  # is not logged in -- and that Module.login_type/0 has tracked it --
  # then terminates the third child, and verifies the third session is closed.
  test "closes sessions when terminated" do
    co_pin = Application.fetch_env!(:p11ex, :co_pin)
    token_label = Application.fetch_env!(:p11ex, :token_label)
    assert {:ok, %{slot_id: slot_id}} = P11ex.Module.find_slot_by_tokenlabel(token_label)

    args1 = [module: P11ex.Module, slot_id: slot_id, name: {:via, Registry, {@registry, {:session, 1}}}]
    assert {:ok, pid1} = DynamicSupervisor.start_child(@supervisor, {P11ex.Session, args1})
    handle1 = pid1 |> :sys.get_state() |> Map.get(:session)

    args2 = [module: P11ex.Module, slot_id: slot_id, name: {:via, Registry, {@registry, {:session, 2}}}]
    assert {:ok, pid2} = DynamicSupervisor.start_child(@supervisor, {P11ex.Session, args2})
    handle2 = pid2 |> :sys.get_state() |> Map.get(:session)

    # not logged in
    assert {:ok, %{state: info}} = P11ex.Lib.session_info(handle1)
    assert :ro_user_functions not in info
    assert P11ex.Module.login_type() == nil

    assert P11ex.Session.login(pid1, :user, co_pin) == :ok

    # logged in
    assert {:ok, %{state: info}} = P11ex.Lib.session_info(handle1)
    assert :ro_user_functions in info
    assert P11ex.Module.login_type() == :user

    assert DynamicSupervisor.terminate_child(@supervisor, pid1) == :ok
    assert P11ex.Lib.session_info(handle1) == {:error, {:C_GetSessionInfo, :ckr_session_handle_invalid}}

    # still logged in
    assert {:ok, %{state: info}} = P11ex.Lib.session_info(handle2)
    assert :ro_user_functions in info
    assert P11ex.Module.login_type() == :user

    assert DynamicSupervisor.terminate_child(@supervisor, pid2) == :ok
    assert P11ex.Lib.session_info(handle2) == {:error, {:C_GetSessionInfo, :ckr_session_handle_invalid}}

    args3 = [module: P11ex.Module, slot_id: slot_id, name: {:via, Registry, {@registry, {:session, 3}}}]
    assert {:ok, pid3} = DynamicSupervisor.start_child(@supervisor, {P11ex.Session, args3})
    handle3 = pid3 |> :sys.get_state() |> Map.get(:session)

    # not logged in
    assert {:ok, %{state: info}} = P11ex.Lib.session_info(handle3)
    assert :ro_user_functions not in info
    assert P11ex.Module.login_type() == nil

    assert DynamicSupervisor.terminate_child(@supervisor, pid3) == :ok
    assert P11ex.Lib.session_info(handle3) == {:error, {:C_GetSessionInfo, :ckr_session_handle_invalid}}
  end

end
