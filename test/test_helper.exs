# Set PKCS11_MODULE to SoftHSM2 module path, depending on OS

if System.get_env("PKCS11_MODULE") == nil do
  softhsm_path = case :os.type() do
    {:unix, :darwin} -> "/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so"
    {:unix, :linux} -> "/usr/lib/softhsm/libsofthsm2.so"
    _ -> raise "Unsupported operating system"
  end

  System.put_env("PKCS11_MODULE", softhsm_path)
end

defmodule P11ex.TestHelper do

  import ExUnit.Assertions
  require Logger
  def get_module_path!() do
    System.get_env("PKCS11_MODULE") ||
      raise "Environment variable PKCS11_MODULE is not set."
  end

  def setup_session do
    Logger.info("test/setup_session: Starting")

    {:ok, slot} = P11ex.Module.find_slot_by_tokenlabel("Token_0")
    assert slot != nil

    Logger.info("test/setup_session: Starting Session GenServer for slot #{slot.slot_id}")
    {:ok, session_pid} = P11ex.Session.start_link([
      module: P11ex.Module,
      slot_id: slot.slot_id,
      flags: [:rw_session, :serial_session]
    ])

    Logger.info("test/setup_session: Logging into session pid=#{inspect(session_pid)}")
    co_pin = Application.fetch_env!(:p11ex, :co_pin)
    :ok = P11ex.Session.login(session_pid, :user, co_pin)

    Logger.info("test/setup_session: Setup complete")
    {:ok, %{
      slot: slot,
      session_pid: session_pid,
      token_label: "Token_0"
    }}
  end

end

defmodule TestSupervisor do
  use Supervisor

  require Logger

  def start_link(init_arg) do
    Supervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  @impl true
  def init(_init_arg) do
    Logger.info("Starting TestSupervisor")

    module_path = P11ex.TestHelper.get_module_path!()
    Logger.info("Module path: #{module_path}")

    children = [
      {P11ex.Module, module_path}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end

# Start the supervisor and Module process before running tests
{:ok, _pid} = TestSupervisor.start_link([])

ExUnit.configure(
  formatters: [JUnitFormatter, ExUnit.CLIFormatter],
  async: false  # Disable async execution globally
)

ExUnit.start()
