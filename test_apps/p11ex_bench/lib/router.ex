defmodule P11exBench.Router do
  use Plug.Router

  plug :match
  plug Plug.Parsers,
    parsers: [:json],
    pass: ["application/json", "application/octet-stream"],
    json_decoder: Jason,
    length: 10_000_000

  plug :match
  plug :dispatch

  get "/health" do
    send_resp(conn, 200, "OK")
  end

  get "/slots" do
    case P11exBench.Controllers.General.list_slots(conn) do
      {:ok, slots} ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(200, Jason.encode!(%{slots: slots}))
      {:error, reason} ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(500, Jason.encode!(%{error: reason}))
    end
  end

  get "/crypto/random" do
    case P11exBench.Controllers.General.generate_random(conn) do
      {:ok, random} ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(200, Jason.encode!(%{random: Base.encode64(random)}))
      {:error, reason} ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(500, Jason.encode!(%{error: reason}))
    end
  end

  post "/token/secret-key/aes" do
    case conn.body_params do
      %{"label" => label, "key_size" => key_size} when key_size in [16, 24, 32] ->
        case P11exBench.Controllers.Aes.generate_token_key(label, key_size) do
          {:ok, key_info} ->
            conn
            |> put_resp_content_type("application/json")
            |> send_resp(200, Jason.encode!(key_info))
          {:error, reason} ->
            conn
            |> put_resp_content_type("application/json")
            |> send_resp(500, Jason.encode!(%{error: reason}))
        end
      _ ->
        conn
          |> put_resp_content_type("application/json")
          |> send_resp(400, Jason.encode!(%{error: "Invalid parameters. Required: label (string) and key_size (16, 24, or 32)"}))
    end
  end

  post "/token/secret-key/aes/encrypt/:key_handle" do
    case Plug.Conn.read_body(conn, length: 10_000_000) do
      {:ok, plaintext, conn} ->
        case P11exBench.Controllers.Aes.encrypt(String.to_integer(key_handle), plaintext) do
          {:ok, ciphertext} ->
            conn
            |> put_resp_content_type("application/octet-stream")
            |> send_resp(200, ciphertext)
          {:error, reason} ->
            conn
            |> put_resp_content_type("application/json")
            |> send_resp(500, Jason.encode!(%{error: reason}))
        end
      {:more, _, _} ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(413, Jason.encode!(%{error: "Request body too large"}))
      {:error, :timeout} ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(408, Jason.encode!(%{error: "Request timeout"}))
      {:error, _} ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(400, Jason.encode!(%{error: "Invalid request body"}))
    end
  end

  post "/token/secret-key/aes/encrypt-chunks/:key_handle" do
    case Plug.Conn.read_body(conn, length: 10_000_000) do
      {:ok, plaintext, conn} ->
        case P11exBench.Controllers.Aes.encrypt_chunks(String.to_integer(key_handle), plaintext) do
          {:ok, ciphertext} ->
            P11exBench.Metrics.p11ex_crypto_operations_total(:inc, operation: "aes_encrypt_chunks", status: "success")
            conn
            |> put_resp_content_type("application/octet-stream")
            |> send_resp(200, ciphertext)
          {:error, reason} ->
            P11exBench.Metrics.p11ex_crypto_operations_total(:inc, operation: "aes_encrypt_chunks", status: "error")
            conn
            |> put_resp_content_type("application/json")
            |> send_resp(500, Jason.encode!(%{error: reason}))
          other ->
            IO.inspect(other, label: "other")
        end
      {:more, _, _} ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(413, Jason.encode!(%{error: "Request body too large"}))
      {:error, :timeout} ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(408, Jason.encode!(%{error: "Request timeout"}))
      {:error, _} ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(400, Jason.encode!(%{error: "Invalid request body"}))
    end
  end
end
