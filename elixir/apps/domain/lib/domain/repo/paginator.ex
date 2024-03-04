defmodule Domain.Repo.Paginator do
  @moduledoc """
  This module implements simple keyset-based pagination.

  This method of pagination is chosen because it's fast and consistent, especially for
  large datasets (eg. audit logs) and when the data is frequently updated (insertions
  or deletions before the current page will leave the results unaffected).

  It also supports ordering and paging.
  """
  alias Domain.Repo.Query
  import Ecto.Query

  @default_limit 50
  @max_limit 100

  defmodule Metadata do
    # TODO: add count?
    defstruct previous_page_cursor: nil,
              next_page_cursor: nil,
              limit: nil
  end

  def init(query_module, opts) do
    limit = Keyword.get(opts, :limit, @default_limit)
    limit = max(min(limit, @max_limit), 1)

    cursor_fields = Query.fetch_cursor_fields!(query_module)

    if encoded_cursor = Keyword.get(opts, :cursor) do
      with {:ok, {direction, values}} <- decode_cursor(encoded_cursor) do
        {:ok,
         %{
           query_module: query_module,
           cursor_fields: cursor_fields,
           limit: limit,
           direction: direction,
           values: values
         }}
      end
    else
      {:ok,
       %{
         query_module: query_module,
         cursor_fields: cursor_fields,
         limit: limit
       }}
    end
  end

  def query(queryable, paginator_opts) do
    queryable
    |> order_by_cursor_fields(paginator_opts)
    |> maybe_query_page(paginator_opts)
    |> limit_page_size(paginator_opts)
  end

  defp order_by_cursor_fields(queryable, %{cursor_fields: cursor_fields, direction: :before}) do
    # when we paginate backwards we need to flip the orders and
    # then reverse the results in `metadata/3` function
    queryable
    |> default_order_by_cursor_fields(cursor_fields)
    |> Ecto.Query.reverse_order()
  end

  defp order_by_cursor_fields(queryable, %{cursor_fields: cursor_fields}) do
    default_order_by_cursor_fields(queryable, cursor_fields)
  end

  defp default_order_by_cursor_fields(queryable, cursor_fields) do
    Enum.reduce(cursor_fields, queryable, fn {binding, order, field}, queryable ->
      order_by(queryable, [{^binding, b}], [{^order, field(b, ^field)}])
    end)
  end

  defp maybe_query_page(queryable, %{
         direction: direction,
         cursor_fields: cursor_fields,
         values: values
       }) do
    dynamic =
      cursor_fields
      |> Enum.zip(values)
      |> Enum.reverse()
      |> Enum.reduce(nil, fn {field, value}, dynamic ->
        append_by_cursor_dynamic(dynamic, direction, field, value)
      end)

    where(queryable, ^dynamic)
  end

  defp maybe_query_page(queryable, _opts) do
    queryable
  end

  defp append_by_cursor_dynamic(nil, :before, {binding, :asc, field}, value) do
    dynamic([{^binding, b}], field(b, ^field) < ^value)
  end

  defp append_by_cursor_dynamic(dynamic, :before, {binding, :asc, field}, value) do
    dynamic(
      [{^binding, b}],
      field(b, ^field) < ^value or (field(b, ^field) == ^value and ^dynamic)
    )
  end

  defp append_by_cursor_dynamic(nil, :after, {binding, :asc, field}, value) do
    dynamic([{^binding, b}], field(b, ^field) > ^value)
  end

  defp append_by_cursor_dynamic(dynamic, :after, {binding, :asc, field}, value) do
    dynamic(
      [{^binding, b}],
      field(b, ^field) > ^value or (field(b, ^field) == ^value and ^dynamic)
    )
  end

  # Loads `limit`+1 records.

  # Additional record is used to determine if there are more records in the next page,
  # and then is removed from the result set in `metadata/3`.
  defp limit_page_size(queryable, %{limit: limit}) do
    Ecto.Query.limit(queryable, ^(limit + 1))
  end

  def empty_metadata do
    %Metadata{limit: @default_limit}
  end

  def metadata([], %{limit: limit}) do
    {[], %Metadata{limit: limit}}
  end

  # before cursor was used, this means there is a next page exists and results are reversed
  def metadata(results, %{direction: :before, cursor_fields: cursor_fields, limit: limit})
      when length(results) > limit do
    results =
      results
      |> List.delete_at(-1)
      |> Enum.reverse()

    first = List.first(results)
    last = List.last(results)

    metadata =
      %Metadata{
        previous_page_cursor: encode_cursor(:before, cursor_fields, first),
        next_page_cursor: encode_cursor(:after, cursor_fields, last),
        limit: limit
      }

    {results, metadata}
  end

  def metadata(results, %{direction: :before, cursor_fields: cursor_fields, limit: limit}) do
    results = Enum.reverse(results)
    last = List.last(results)

    metadata =
      %Metadata{
        previous_page_cursor: nil,
        next_page_cursor: encode_cursor(:after, cursor_fields, last),
        limit: limit
      }

    {results, metadata}
  end

  # after cursor was used, this means there is a previous page too
  def metadata(results, %{direction: :after, cursor_fields: cursor_fields, limit: limit})
      when length(results) > limit do
    results = List.delete_at(results, -1)
    first = List.first(results)
    last = List.last(results)

    metadata =
      %Metadata{
        previous_page_cursor: encode_cursor(:before, cursor_fields, first),
        next_page_cursor: encode_cursor(:after, cursor_fields, last),
        limit: limit
      }

    {results, metadata}
  end

  def metadata(results, %{direction: :after, cursor_fields: cursor_fields, limit: limit}) do
    first = List.first(results)

    metadata =
      %Metadata{
        previous_page_cursor: encode_cursor(:before, cursor_fields, first),
        next_page_cursor: nil,
        limit: limit
      }

    {results, metadata}
  end

  # no cursor was used
  def metadata(results, %{cursor_fields: cursor_fields, limit: limit})
      when length(results) > limit do
    results = List.delete_at(results, -1)
    last = List.last(results)

    metadata =
      %Metadata{
        previous_page_cursor: nil,
        next_page_cursor: encode_cursor(:after, cursor_fields, last),
        limit: limit
      }

    {results, metadata}
  end

  def metadata(results, %{limit: limit}) do
    metadata =
      %Metadata{
        previous_page_cursor: nil,
        next_page_cursor: nil,
        limit: limit
      }

    {results, metadata}
  end

  @doc false
  def encode_cursor(direction, cursor_fields, schema) do
    values =
      Enum.map(cursor_fields, fn {_binding, _order, field} ->
        Map.fetch!(schema, field)
      end)

    {direction, values}
    |> :erlang.term_to_binary()
    |> Base.url_encode64(padding: false)
  end

  defp decode_cursor(encoded) do
    with {:ok, etf} <- Base.url_decode64(encoded, padding: false),
         {direction, values} <- Plug.Crypto.non_executable_binary_to_term(etf, [:safe]),
         false <- Enum.any?(values, &is_nil/1) do
      {:ok, {direction, values}}
    else
      _ -> {:error, :invalid_cursor}
    end
  rescue
    _e -> {:error, :invalid_cursor}
  end
end
