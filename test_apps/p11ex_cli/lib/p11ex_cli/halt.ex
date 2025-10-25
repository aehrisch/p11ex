defmodule P11exCli.HaltBehaviour do
  @callback halt(atom()) :: no_return()
  @callback halt() :: no_return()
end

defmodule P11exCli.RealHalt do
  @behaviour P11exCli.HaltBehaviour

  def halt(:ok), do: System.halt(0)
  def halt(:error), do: System.halt(1)
  def halt(:invalid_param), do: System.halt(2)
  def halt(), do: System.halt(1)
end
