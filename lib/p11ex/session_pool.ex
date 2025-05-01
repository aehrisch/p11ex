defmodule P11ex.SessionPoolSupervisor do
  use Supervisor

  def start_link(args) do
    Supervisor.start_link(__MODULE__, args)
  end

  def init(args) do

    # required keywors for P11ex.Session
    slot_id = Keyword.get(args, :session_slot_id)
    flags = Keyword.get(args, :session_flags, [:rw_session, :serial_session])

    name = Keyword.get(args, :pool_name, __MODULE__)
    size = Keyword.get(args, :pool_size, 10)
    max_overflow = Keyword.get(args, :pool_max_overflow, 5)

    pool_options = [
      name: {:local, name},
      worker_module: P11ex.Session,
      size: size,
      max_overflow: max_overflow
    ]

    children = [
      :poolboy.child_spec(name, pool_options,
        [module: P11ex.Module, slot_id: slot_id, flags: flags])
    ]

    supervise(children, strategy: :one_for_one)
  end
end
