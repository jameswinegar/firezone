defmodule Domain.Actors.Actor.Query do
  use Domain, :query

  def all do
    from(actors in Domain.Actors.Actor, as: :actors)
  end

  def not_deleted do
    all()
    |> where([actors: actors], is_nil(actors.deleted_at))
  end

  def not_disabled(queryable \\ not_deleted()) do
    where(queryable, [actors: actors], is_nil(actors.disabled_at))
  end

  def by_id(queryable, {:in, ids}) do
    where(queryable, [actors: actors], actors.id in ^ids)
  end

  def by_id(queryable, {:not, id}) do
    where(queryable, [actors: actors], actors.id != ^id)
  end

  def by_id(queryable, id) do
    where(queryable, [actors: actors], actors.id == ^id)
  end

  def by_account_id(queryable, account_id) do
    where(queryable, [actors: actors], actors.account_id == ^account_id)
  end

  def by_type(queryable, type) do
    where(queryable, [actors: actors], actors.type == ^type)
  end

  # Pagination

  @impl Domain.Repo.Query
  def cursor_fields, do: [:inserted_at, :id]

  @impl Domain.Repo.Query
  def order_by_cursor_fields(queryable) do
    order_by(queryable, [actors: actors], asc: actors.inserted_at, asc: actors.id)
  end

  @impl Domain.Repo.Query
  def by_cursor(queryable, :after, [inserted_at, id]) do
    where(
      queryable,
      [actors: actors],
      actors.inserted_at > ^inserted_at or
        (actors.inserted_at == ^inserted_at and actors.id > ^id)
    )
  end

  def by_cursor(queryable, :before, [inserted_at, id]) do
    where(
      queryable,
      [actors: actors],
      actors.inserted_at < ^inserted_at or
        (actors.inserted_at == ^inserted_at and actors.id < ^id)
    )
  end

  # Preloads

  def preload_few_groups_for_each_actor(queryable, limit) do
    queryable
    |> with_joined_memberships(limit)
    |> with_joined_groups()
    |> with_joined_group_counts()
    |> select([actors: actors, groups: groups, group_counts: group_counts], %{
      id: actors.id,
      count: group_counts.count,
      item: groups
    })
  end

  def select_distinct_ids(queryable) do
    queryable
    |> select([actors: actors], actors.id)
    |> distinct(true)
  end

  def with_joined_memberships(queryable, limit) do
    subquery =
      Domain.Actors.Membership.Query.all()
      |> where([memberships: memberships], memberships.actor_id == parent_as(:actors).id)
      # we need second join to exclude soft deleted actors before applying a limit
      |> join(
        :inner,
        [memberships: memberships],
        groups in ^Domain.Actors.Group.Query.not_deleted(),
        on: groups.id == memberships.group_id
      )
      |> select([memberships: memberships], memberships.group_id)
      |> limit(^limit)

    join(queryable, :cross_lateral, [actors: actors], memberships in subquery(subquery),
      as: :memberships
    )
  end

  def with_joined_group_counts(queryable) do
    subquery =
      Domain.Actors.Membership.Query.count_groups_by_actor_id()
      |> where([memberships: memberships], memberships.actor_id == parent_as(:actors).id)

    join(queryable, :cross_lateral, [actors: actors], group_counts in subquery(subquery),
      as: :group_counts
    )
  end

  def with_joined_groups(queryable) do
    join(
      queryable,
      :left,
      [memberships: memberships],
      groups in ^Domain.Actors.Group.Query.not_deleted(),
      on: groups.id == memberships.group_id,
      as: :groups
    )
  end

  def with_joined_clients(queryable) do
    join(
      queryable,
      :left,
      [actors: actors],
      clients in ^Domain.Clients.Client.Query.not_deleted(),
      on: clients.actor_id == actors.id,
      as: :clients
    )
  end

  def lock(queryable) do
    lock(queryable, "FOR UPDATE")
  end

  def with_assoc(queryable, qual \\ :left, assoc) do
    with_named_binding(queryable, assoc, fn query, binding ->
      join(query, qual, [actors: actors], a in assoc(actors, ^binding), as: ^binding)
    end)
  end

  def filters do
  end
end
