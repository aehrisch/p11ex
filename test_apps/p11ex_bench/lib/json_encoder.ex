defmodule P11exBench.JSONEncoder do
  @moduledoc """
  Custom JSON encoder for P11exBench types that need special handling.
  Currently handles:
  - MapSet encoding by converting it to a list
  - Tuple encoding by converting it to a list
  """

  defimpl Jason.Encoder, for: MapSet do
    def encode(mapset, opts) do
      Jason.Encode.list(MapSet.to_list(mapset), opts)
    end
  end

  defimpl Jason.Encoder, for: Tuple do
    def encode(tuple, opts) do
      Jason.Encode.list(Tuple.to_list(tuple), opts)
    end
  end
end
