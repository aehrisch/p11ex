import Config

config :p11ex_cli,
  :exit_mod, P11exCli.RealHalt

config :p11ex_cli,
  :benchmark,
  block_sizes: [32, 256, 1024, 8192, 65536, 262144],
  rounds_per_block: 10  # Default number of rounds per block size

import_config "#{config_env()}.exs"
