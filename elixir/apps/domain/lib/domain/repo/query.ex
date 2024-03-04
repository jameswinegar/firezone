defmodule Domain.Repo.Query do
  alias Domain.Repo.Filter
  import Ecto.Query

  @type direction :: :after | :before

  @type preload_fun ::
          ([Ecto.Schema.t()] -> [Ecto.Schema.t()]) | Ecto.Queryable.t() | (-> Ecto.Queryable.t())
  @type preload_funs :: [{atom(), preload_fun()} | {atom(), {preload_fun(), preload_funs()}}]

  @doc """
  Returns list of fields that are used for cursor based pagination.
  """
  @callback cursor_fields() :: [
              {binding :: atom(), :asc | :desc, field :: atom()}
            ]

  @doc """
  Allows to define custom preloads for the schema.

  Each preload is defined as a function that overrides `Repo.preload/2` default behavior for a key.

  The function either accepts a list of schemas and returns either a list of schemas,
  or no arguments and returns a queryable that will be used to preload the association.
  """
  @callback preloads() :: preload_funs()

  @doc """
  Defines available user-facing filters for the schema.
  """
  @callback filters() :: [Domain.Repo.Filter.t()]

  @optional_callbacks [
    cursor_fields: 0,
    preloads: 0,
    filters: 0
  ]

  # Callback helpers

  def fetch_cursor_fields!(query_module) do
    query_module.cursor_fields()
  end

  def get_preloads_funs(query_module) do
    _ = Code.ensure_loaded(query_module)

    if Kernel.function_exported?(query_module, :preloads, 0) do
      query_module.preloads()
    else
      []
    end
  end

  def get_filters(query_module) do
    _ = Code.ensure_loaded(query_module)

    if Kernel.function_exported?(query_module, :filters, 0) do
      query_module.filters()
    else
      []
    end
  end

  # Filtering helpers

  @doc """
  Allows to easily define range filter callback for the given `field`.

  ## Example

      fn queryable, range ->
        {queryable, by_range(range, accounts.inserted_at)}
      end
  """
  def by_range(%Filter.Range{from: from, to: nil}, fragment),
    do: dynamic(^fragment >= ^from)

  def by_range(%Filter.Range{from: nil, to: to}, fragment),
    do: dynamic(^fragment <= ^to)

  def by_range(%Filter.Range{from: value, to: value}, fragment),
    do: dynamic(^fragment == ^value)

  def by_range(%Filter.Range{from: from, to: to}, fragment),
    do: dynamic(^from <= ^fragment and ^fragment <= ^to)

  def by_range(%Filter.Range{to: to}, fragment),
    do: dynamic(^fragment <= ^to)

  def by_range(%Filter.Range{from: from}, fragment),
    do: dynamic(^fragment >= ^from)

  @doc """
  This function is to allow reuse of the filter function in the regular query helpers,
  it takes a return of a filter function (`{queryable, dynamic}`) and applies it to the queryable.

  ## Example

        def by_account_id(queryable, account_id) do
          by_account_id_filter(queryable, account_id)
          |> apply_filter()
        end

        def by_account_id_filter(queryable, account_id) do
          {queryable, dynamic([accounts: accounts], accounts.id == ^account_id)}
        end
  """
  def apply_filter({%Ecto.Query{} = queryable, %Ecto.Query.DynamicExpr{} = dynamic}) do
    where(queryable, ^dynamic)
  end

  @doc """
  This function is to allow to chain the filter functions, it takes a return of
  a filter function (`{queryable, dynamic}`) and appends a return of a new filter to it.

  ## Example

        queryable
        |> append_filter(&by_account_id_filter(&1, account_id))
        |> append_filter(&by_name_filter(&1, name))

  """
  def append_filter(queryable, fun) when is_function(fun, 1) do
    {queryable, dynamic} = fun.(queryable)
    apply_filter({queryable, dynamic})
  end

  # Custom Query fragments

  @doc """
  Uses a combination Postgres full-text search and ILIKE to query the given `field` with the given `search_query`.

  ## Supported query features

  Quoted word sequences are converted to phrase tests. The word “or” is understood as producing an OR operator,
  and a dash produces a NOT operator; other punctuation is ignored.

  Examples:

      `fulltext_search(:name, "hello world")` will search for the phrase "hello world"
      `fulltext_search(:name, "hello or world")` will search for "hello" or "world"
      `fulltext_search(:name, "hello -world")` will search for "hello" but not "world"


  ## How to index a column for full-text search

  To make sure that search is efficient you need to have a GIN index on the column you want to search.

  You can create the `tsvector` using a migration like this:

      CREATE INDEX my_table_column_name_fulltext_idx ON my_table USING gin(to_tsvector('english', column_name))

  For `ILIKE` a separate trigram GIN index is needed:

      CREATE INDEX my_table_column_name_trigram_idx ON my_table USING gin(unaccent(column_name) gin_trgm_ops)

  """
  defmacro fulltext_search(field, search_query) do
    quote do
      fragment(
        "(to_tsvector('english', ?) @@ websearch_to_tsquery(?) OR unaccent(?) ILIKE '%' || unaccent(?) || '%')",
        unquote(field),
        unquote(search_query),
        unquote(field),
        unquote(search_query)
      )
    end
  end
end
