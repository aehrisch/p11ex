defmodule P11exCli.BenchAesEncryptBlockTest do

  use ExUnit.Case, async: false
  import ExUnit.CaptureIO

  alias P11exCli.TestHelper, as: TH

  setup_all do
    TH.setup_all()
  end

  describe "bench-aes-encrypt-block" do

    test "happy path with single session", context do
      output = capture_io(fn ->
        P11exCli.BenchAesEncryptBlock.main(context.token_args ++ ["label:aes_128"])
      end)

      assert {:ok, result} = Jason.decode(output)
      assert Map.has_key?(result, "measurements")
      assert Map.has_key?(result, "config")
      assert length(result["measurements"]) > 0
      assert Map.get(result, "config") |> Map.get("number_sessions") == 1
    end

    test "happy path with multiple sessions", context do
      output = capture_io(fn ->
        P11exCli.BenchAesEncryptBlock.main(context.token_args ++ ["--number-sessions", "4", "label:aes_128"])
      end)

      assert {:ok, result} = Jason.decode(output)
      assert Map.has_key?(result, "measurements")
      assert Map.get(result, "config") |> Map.get("number_sessions") == 4
    end

    test "verify JSON output structure", context do
      output = capture_io(fn ->
        P11exCli.BenchAesEncryptBlock.main(context.token_args ++ ["label:aes_128"])
      end)

      assert {:ok, result} = Jason.decode(output)

      # Check top-level keys
      assert Map.has_key?(result, "measurements")
      assert Map.has_key?(result, "config")

      # Check measurements structure
      measurements = result["measurements"]
      assert is_list(measurements)
      assert length(measurements) > 0

      # Check first measurement structure
      first_measurement = List.first(measurements)
      assert Map.has_key?(first_measurement, "block_size_bytes")
      assert Map.has_key?(first_measurement, "status")
      assert Map.has_key?(first_measurement, "rounds")

      # If status is success, should have average_duration_ms
      if first_measurement["status"] == "success" do
        assert Map.has_key?(first_measurement, "average_duration_ms")
        assert is_number(first_measurement["average_duration_ms"])
      end

      # Check config structure
      config = result["config"]
      assert Map.has_key?(config, "key_ref")
      assert Map.has_key?(config, "number_sessions")
      assert Map.has_key?(config, "iv")
      assert Map.has_key?(config, "block_sizes")
      assert Map.has_key?(config, "rounds_per_block")
    end

    test "missing key reference", context do
      output = capture_io(fn ->
        assert_raise RuntimeError, fn ->
          P11exCli.BenchAesEncryptBlock.main(context.token_args ++ ["label:nonexistent_key"])
        end
      end)
      # Should error when key not found
    end

    test "custom rounds option", context do
      output = capture_io(fn ->
        P11exCli.BenchAesEncryptBlock.main(context.token_args ++ ["--rounds", "5", "label:aes_128"])
      end)

      assert {:ok, result} = Jason.decode(output)
      assert Map.has_key?(result, "measurements")
      assert Map.has_key?(result, "config")
      # Should use custom rounds value
      assert Map.get(result, "config") |> Map.get("rounds_per_block") == 5
    end

    test "show usage" do
      output = capture_io(fn ->
        P11exCli.main(["help", "bench-aes-encrypt-block"])
      end)

      assert output =~ ~r/Arguments\n/
      assert output =~ ~r/Options\n/
      assert output =~ ~r/\-\-token\-label/
      assert output =~ ~r/\-\-number\-sessions/
      assert output =~ ~r/\-\-rounds/
    end

  end
end
