defmodule P11exBench.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {PrometheusTelemetry,
        exporter: [enabled?: true],
        metrics: [
          PrometheusTelemetry.Metrics.VM.metrics(),
          PrometheusTelemetry.Metrics.Cowboy.metrics()
        ]
      },
      {Plug.Cowboy, scheme: :http, plug: P11exBench.Router, options: [port: 4000]},
      {P11ex.Module, "/Users/eric/hack/softhsm/lib/softhsm/libsofthsm2.so"}
      #{P11ex.Module, "/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so"}
    ]

    opts = [strategy: :one_for_one, name: P11ExBench.Supervisor]
    {:ok, sup} = Supervisor.start_link(children, opts)

    # Find the slot with token label "Token_0"
    {:ok, slot} = P11ex.Module.find_slot_by_tokenlabel("Token_0")

    # Add the session pool supervisor to the supervision tree
    {:ok, _session_pool_sup} =
        Supervisor.start_child(sup, {P11ex.SessionPoolSupervisor, [
          session_slot_id: slot.slot_id,
          pool_name: P11exBench.SessionPool,
          pool_size: 10,
          pool_max_overflow: 5
        ]})

    {:ok, sup}
  end
end
