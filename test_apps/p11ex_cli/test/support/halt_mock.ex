defmodule P11exCli.HaltMock do

  def halt(:ok) do
    send(self(), {:halt_called, :ok})
  end

  def halt(code) do
    send(self(), {:halt_called, code})
    raise "halt-error"
  end

  def halt() do
    IO.puts("#### Halt called with no args")
    send(self(), {:halt_called, :no_args})
    raise "Halt called with no args"
  end
end
