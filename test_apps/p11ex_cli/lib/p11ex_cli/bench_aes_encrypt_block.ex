defmodule P11exCli.BenchAesEncryptBlock do
  alias CliMate.CLI

  defp exit, do: Application.fetch_env!(:p11ex_cli, :exit_mod)

  @command name: "p11ex bench-aes-encrypt-block",
    module: __MODULE__,
    options: P11exCli.Common.options() ++ P11exCli.Common.token_options() ++ [
      number_sessions: [
        type: :integer,
        required: false,
        default: 1,
        doc: "Number of parallel sessions to use for benchmarking"
      ],
      rounds: [
        type: :integer,
        required: false,
        doc: "Number of rounds per block size (overrides config)"
      ]
    ],
    arguments: [
      key_ref: [
        type: :string,
        required: true,
        doc: "Reference to secret key (label:name, id:hex, or handle:number)"
      ]
    ]

  def main(args) do
    case CLI.parse(args, @command) do
      {:ok, res} ->
        execute_benchmark(res)
      {:error, reason} ->
        IO.puts("Error parsing arguments: #{inspect(reason)}")
        exit().halt(:invalid_param)
    end
  end

  defp execute_benchmark(res) do
    P11exCli.Common.load_module(res.options)
    slot = P11exCli.Common.find_slot_by_label!(res.options)
    {:ok, initial_session_pid} = P11exCli.Common.login!(slot, res.options)

    # Find the secret key
    key = P11exCli.Common.find_key_by_ref!(initial_session_pid, res.arguments.key_ref, :cko_secret_key)

    # Get configuration
    config =Application.fetch_env!(:p11ex_cli, :benchmark)
    block_sizes = Keyword.get(config, :block_sizes)

    # Use --rounds option if provided, otherwise use config default
    rounds_per_block = Map.get(res.options, :rounds) || Keyword.get(config, :rounds_per_block)

    # Generate IV once for all encryptions
    iv = :crypto.strong_rand_bytes(16)

    # Generate random data blocks for each size
    data_blocks = Enum.map(block_sizes, fn size ->
      {size, :crypto.strong_rand_bytes(size)}
    end)

    # Setup poolboy pool
    pool_size = res.options.number_sessions
    {:ok, pool} = setup_pool(slot, res.options, pool_size)

    try do
      # Execute benchmarks
      {total_duration_us, measurements} = :timer.tc(fn ->
        run_benchmarks(pool, key, iv, data_blocks, rounds_per_block)
      end)

      # Build output structure
      output = %{
        total_duration_ms: total_duration_us / 1000,
        measurements: measurements,
        config: %{
          key_ref: res.arguments.key_ref,
          number_sessions: res.options.number_sessions,
          iv: "0x" <> Base.encode16(iv, case: :lower),
          block_sizes: block_sizes,
          rounds_per_block: rounds_per_block
        }
      }

      # Pretty print JSON
      IO.puts(Jason.encode!(output, pretty: true))

      P11ex.Session.logout(initial_session_pid)
      exit().halt(:ok)
    after
      # Cleanup pool
      :poolboy.stop(pool)
    end
  end

  defp setup_pool(slot, options, size) do
    pool_options = [
      name: {:local, :benchmark_pool},
      worker_module: P11ex.Session,
      size: size,
      max_overflow: 0
    ]

    pool_args = [
      module: P11ex.Module,
      slot_id: slot.slot_id,
      flags: [:rw_session]
    ]

    pin = P11exCli.Common.get_pin!(options)
    pool_spec = :poolboy.child_spec(:benchmark_pool, pool_options, pool_args)

    # Start the supervisor
    {:ok, _pool_supervisor} = Supervisor.start_link([pool_spec], strategy: :one_for_one)

    # Login all workers in the pool
    Enum.each(1..size, fn _ ->
      :poolboy.transaction(:benchmark_pool, fn worker ->
        P11ex.Session.login(worker, :user, pin)
      end)
    end)

    {:ok, :benchmark_pool}
  end

  defp run_benchmarks(pool, key, iv, data_blocks, rounds_per_block) do
    Enum.map(data_blocks, fn {block_size, plaintext} ->
      run_benchmark_for_size(pool, key, iv, plaintext, block_size, rounds_per_block)
    end)
  end

  defp run_benchmark_for_size(pool, key, iv, plaintext, block_size, rounds_per_block) do
    # Run rounds in parallel using the pool
    results = Enum.map(1..rounds_per_block, fn _ ->
      :poolboy.transaction(pool, fn session ->
        execute_encryption(session, key, iv, plaintext)
      end)
    end)

    # Calculate averages
    {durations, errors} = Enum.reduce(results, {[], []}, fn
      {:ok, duration_us}, {acc, acc_err} -> {[duration_us | acc], acc_err}
      {:error, reason}, {acc, acc_err} -> {acc, [reason | acc_err]}
    end)

    cond do
      length(durations) > 0 && length(errors) == 0 ->
        # All succeeded
        avg_duration_ms = Enum.sum(durations) / length(durations) / 1000
        %{
          block_size_bytes: block_size,
          status: "success",
          average_duration_ms: avg_duration_ms,
          rounds: rounds_per_block
        }

      length(durations) > 0 ->
        # Some succeeded, some failed
        avg_duration_ms = Enum.sum(durations) / length(durations) / 1000
        %{
          block_size_bytes: block_size,
          status: "partial",
          average_duration_ms: avg_duration_ms,
          rounds: rounds_per_block,
          succeeded: length(durations),
          failed: length(errors),
          error: inspect(Enum.at(errors, 0))
        }

      true ->
        # All failed
        %{
          block_size_bytes: block_size,
          status: "error",
          rounds: rounds_per_block,
          error: inspect(Enum.at(errors, 0))
        }
    end
  end

  defp execute_encryption(session, key, iv, plaintext) do
    {duration_us, result} = :timer.tc(fn ->
      P11ex.Session.encrypt(session, {:ckm_aes_cbc, %{iv: iv}}, key, plaintext)
    end)

    case result do
      {:ok, _ciphertext} -> {:ok, duration_us}
      error -> error
    end
  end

  def format_usage do
    IO.puts(CLI.format_usage(@command))
  end

end
