import Config

config :p11ex_cli,
  :exit_mod, P11exCli.RealHalt

import_config "#{config_env()}.exs"
