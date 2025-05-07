import Config

config :p11ex,
  token_label: "Token_0",
  co_pin: "1234"

config :ex_unit,
  capture_log: true,
  formatters: [ExUnit.CLIFormatter, JUnitFormatter]
