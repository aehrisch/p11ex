defmodule P11exBench.Router do
  use Plug.Router

  plug :match
  plug Plug.Parsers,
    parsers: [:json],
    pass: ["application/json"],
    json_decoder: Jason
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
  # ... other routes
end
