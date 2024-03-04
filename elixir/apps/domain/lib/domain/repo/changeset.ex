defmodule Domain.Repo.Changeset do
  @moduledoc """
  This module extend `Ecto.Changeset`'s with custom validations and polymorphic embeds.
  """
  import Ecto.Changeset
  alias Ecto.Changeset

  # Helpers

  def has_errors?(%Ecto.Changeset{} = changeset, field) do
    Keyword.has_key?(changeset.errors, field)
  end

  def empty?(%Ecto.Changeset{} = changeset, field) do
    case fetch_field(changeset, field) do
      :error -> true
      {_data_or_changes, nil} -> true
      {_data_or_changes, _value} -> false
    end
  end

  @doc """
  Takes value from `value_field` and puts it's hash of a given type to `hash_field`.
  """
  def put_hash(%Ecto.Changeset{} = changeset, value_field, type, opts) do
    hash_field = Keyword.fetch!(opts, :to)
    salt_field = Keyword.get(opts, :with_salt)
    nonce_field = Keyword.get(opts, :with_nonce)

    with {:ok, value} <- fetch_value(changeset, value_field),
         {:ok, nonce} <- fetch_hash_component(changeset, nonce_field),
         {:ok, salt} <- fetch_hash_component(changeset, salt_field) do
      put_change(changeset, hash_field, Domain.Crypto.hash(type, nonce <> value <> salt))
    else
      _ -> changeset
    end
  end

  defp fetch_value(%Ecto.Changeset{} = changeset, value_field) do
    case fetch_change(changeset, value_field) do
      {:ok, ""} -> :error
      {:ok, value} when is_binary(value) -> {:ok, value}
      _other -> :error
    end
  end

  defp fetch_hash_component(_changeset, nil) do
    {:ok, ""}
  end

  defp fetch_hash_component(changeset, salt_field) do
    case fetch_change(changeset, salt_field) do
      {:ok, salt} when is_binary(salt) -> {:ok, salt}
      :error -> {:ok, ""}
    end
  end

  @doc """
  Removes change for a given field and original value from it from `changeset.params`.

  Even though `changeset.params` considered to be a private field it leaks values even
  after they are removed from a changeset if you `inspect(struct, structs: false)` or
  just access it directly.
  """
  def redact_field(%Ecto.Changeset{} = changeset, field) do
    changeset = delete_change(changeset, field)
    %{changeset | params: Map.drop(changeset.params, field_variations(field))}
  end

  defp field_variations(field) when is_atom(field), do: [field, Atom.to_string(field)]

  @doc """
  Puts the change if field is not changed or it's value is set to `nil`.
  """
  def put_default_value(%Ecto.Changeset{} = changeset, _field, nil) do
    changeset
  end

  def put_default_value(%Ecto.Changeset{} = changeset, field, from: source_field) do
    case fetch_field(changeset, source_field) do
      {_data_or_changes, value} -> put_default_value(changeset, field, value)
      :error -> changeset
    end
  end

  def put_default_value(%Ecto.Changeset{} = changeset, field, value) do
    case fetch_field(changeset, field) do
      {:data, nil} -> put_change(changeset, field, maybe_apply(changeset, value))
      :error -> put_change(changeset, field, maybe_apply(changeset, value))
      _ -> changeset
    end
  end

  defp maybe_apply(_changeset, fun) when is_function(fun, 0), do: fun.()
  defp maybe_apply(changeset, fun) when is_function(fun, 1), do: fun.(changeset)
  defp maybe_apply(_changeset, value), do: value

  def trim_change(%Ecto.Changeset{} = changeset, field) do
    update_change(changeset, field, fn
      nil -> nil
      changes when is_list(changes) -> Enum.map(changes, &String.trim/1)
      change -> String.trim(change)
    end)
  end

  def copy_change(%Ecto.Changeset{} = changeset, from, to) do
    case fetch_change(changeset, from) do
      {:ok, nil} -> changeset
      {:ok, value} -> put_change(changeset, to, value)
      :error -> changeset
    end
  end

  # Validations

  def validate_email(%Ecto.Changeset{} = changeset, field) do
    changeset
    |> validate_format(field, ~r/^[^\s]+@[^\s]+$/, message: "is an invalid email address")
    |> validate_length(field, max: 160)
  end

  def validate_does_not_end_with(%Ecto.Changeset{} = changeset, field, suffix, opts \\ []) do
    validate_change(changeset, field, fn _current_field, value ->
      if String.ends_with?(value, suffix) do
        message = Keyword.get(opts, :message, "can not end with #{inspect(suffix)}")
        [{field, message}]
      else
        []
      end
    end)
  end

  def validate_uri(%Ecto.Changeset{} = changeset, field, opts \\ []) when is_atom(field) do
    valid_schemes = Keyword.get(opts, :schemes, ~w[http https])
    require_trailing_slash? = Keyword.get(opts, :require_trailing_slash, false)

    validate_change(changeset, field, fn _current_field, value ->
      case URI.new(value) do
        {:ok, %URI{} = uri} ->
          cond do
            uri.host == nil or uri.host == "" ->
              [{field, "does not contain a scheme or a host"}]

            uri.scheme == nil ->
              [{field, "does not contain a scheme"}]

            uri.scheme not in valid_schemes ->
              [{field, "only #{Enum.join(valid_schemes, ", ")} schemes are supported"}]

            require_trailing_slash? and not is_nil(uri.path) and
                not String.ends_with?(uri.path, "/") ->
              [{field, "does not end with a trailing slash"}]

            true ->
              []
          end

        {:error, part} ->
          [{field, "is invalid. Error at #{part}"}]
      end
    end)
  end

  def normalize_url(%Ecto.Changeset{} = changeset, field) do
    with {:ok, value} <- fetch_change(changeset, field),
         false <- has_errors?(changeset, field) do
      uri = URI.parse(value)
      scheme = uri.scheme || "https"
      port = uri.port || URI.default_port(scheme)
      path = maybe_add_trailing_slash(uri.path || "/")
      uri = %{uri | scheme: scheme, port: port, path: path}
      uri_string = URI.to_string(uri)
      put_change(changeset, field, uri_string)
    else
      _ -> changeset
    end
  end

  defp maybe_add_trailing_slash(value) do
    if String.ends_with?(value, "/") do
      value
    else
      value <> "/"
    end
  end

  def validate_one_of(%Ecto.Changeset{} = changeset, field, validators) do
    validate_change(changeset, field, fn current_field, _value ->
      orig_errors = Enum.filter(changeset.errors, &(elem(&1, 0) == current_field))

      Enum.reduce_while(validators, [], fn validator, errors ->
        validated_cs = validator.(changeset, current_field)

        new_errors =
          Enum.filter(validated_cs.errors, &(elem(&1, 0) == current_field)) -- orig_errors

        if Enum.empty?(new_errors) do
          {:halt, new_errors}
        else
          {:cont, new_errors ++ errors}
        end
      end)
    end)
  end

  def validate_not_in_cidr(%Ecto.Changeset{} = changeset, ip_or_cidr_field, cidr, opts \\ []) do
    validate_change(changeset, ip_or_cidr_field, fn _ip_or_cidr_field, ip_or_cidr ->
      case Domain.Types.INET.cast(ip_or_cidr) do
        {:ok, ip_or_cidr} ->
          if Domain.Types.CIDR.contains?(cidr, ip_or_cidr) or
               Domain.Types.CIDR.contains?(ip_or_cidr, cidr) do
            message = Keyword.get(opts, :message, "can not be in the CIDR #{cidr}")
            [{ip_or_cidr_field, message}]
          else
            []
          end

        _other ->
          []
      end
    end)
  end

  def validate_and_normalize_cidr(%Ecto.Changeset{} = changeset, field, _opts \\ []) do
    with {_data_or_changes, value} <- fetch_change(changeset, field),
         {:ok, cidr} <- Domain.Types.CIDR.cast(value) do
      {range_start, _range_end} = Domain.Types.CIDR.range(cidr)
      cidr = %{cidr | address: range_start}
      put_change(changeset, field, to_string(cidr))
    else
      :error ->
        changeset

      {:error, _reason} ->
        add_error(changeset, field, "is not a valid CIDR range")
    end
  end

  def validate_and_normalize_ip(%Ecto.Changeset{} = changeset, field, _opts \\ []) do
    with {_data_or_changes, value} <- fetch_change(changeset, field),
         {:ok, ip} <- Domain.Types.IP.cast(value) do
      put_change(changeset, field, to_string(ip))
    else
      :error ->
        changeset

      {:error, _reason} ->
        add_error(changeset, field, "is not a valid IP address")
    end
  end

  def validate_base64(%Ecto.Changeset{} = changeset, field) do
    validate_change(changeset, field, fn _cur, value ->
      case Base.decode64(value) do
        :error -> [{field, "must be a base64-encoded string"}]
        {:ok, _decoded} -> []
      end
    end)
  end

  @doc """
  Validates that value in a given `value_field` equals to hash stored in `hash_field`.
  """
  def validate_hash(%Ecto.Changeset{} = changeset, value_field, type, hash_field: hash_field) do
    with {:data, hash} <- fetch_field(changeset, hash_field) do
      validate_change(changeset, value_field, fn value_field, token ->
        if Domain.Crypto.equal?(type, token, hash) do
          []
        else
          [{value_field, {"is invalid", [validation: :hash]}}]
        end
      end)
    else
      {:changes, _hash} ->
        add_error(changeset, value_field, "can't be verified", validation: :hash)

      :error ->
        add_error(changeset, value_field, "is already verified", validation: :hash)
    end
  end

  def validate_required_one_of(%Ecto.Changeset{} = changeset, fields) do
    if Enum.any?(fields, &(not empty?(changeset, &1))) do
      changeset
    else
      Enum.reduce(
        fields,
        changeset,
        &add_error(&2, &1, "one of these fields must be present: #{Enum.join(fields, ", ")}",
          validation: :one_of,
          one_of: fields
        )
      )
    end
  end

  def validate_datetime(%Ecto.Changeset{} = changeset, field, greater_than: greater_than) do
    validate_change(changeset, field, fn _current_field, value ->
      if DateTime.compare(value, greater_than) == :gt do
        []
      else
        [{field, "must be greater than #{inspect(greater_than)}"}]
      end
    end)
  end

  def validate_date(%Ecto.Changeset{} = changeset, field, greater_than: greater_than) do
    validate_change(changeset, field, fn _current_field, value ->
      if Date.compare(value, greater_than) == :gt do
        []
      else
        [{field, "must be greater than #{inspect(greater_than)}"}]
      end
    end)
  end

  # Polymorphic embeds

  @doc """
  Changes `Ecto.Changeset` struct to convert one of `:map` fields to an embedded schema.

  If embedded changeset was valid, changes would be put back as map to the changeset field
  before the database insert. No embedded validation is performed if there already was an
  error on `field`.

  ## Why not `Ecto.Type`?

  This design is chosen over custom `Ecto.Type` because it allows us to properly build `Ecto.Changeset`
  struct and return errors in a form that will be supported by Phoenix form helpers, while the type
  doesn't allow to return multiple errors when `c:Ecto.Type.cast/2` returns an error tuple.

  ## Options

    * `:with` - callback that accepts attributes as arguments and returns a changeset
    for embedded field. Function signature: `(current_attrs, attrs) -> Ecto.Changeset.t()`.

    * `:required` - if the embed is a required field, default - `false`. Only applies on
    non-list embeds.
  """
  @spec cast_polymorphic_embed(
          changeset :: Changeset.t(),
          field :: atom(),
          opts :: [
            {:required, boolean()},
            {:with, (current_attrs :: map(), attrs :: map() -> Changeset.t())}
          ]
        ) :: Changeset.t()
  def cast_polymorphic_embed(changeset, field, opts) do
    on_cast = Keyword.fetch!(opts, :with)
    required? = Keyword.get(opts, :required, false)

    # We only support singular polymorphic embeds for now
    :map = Map.get(changeset.types, field)

    if field_invalid?(changeset, field) do
      changeset
    else
      data = Map.get(changeset.data, field)
      changes = get_change(changeset, field)

      if required? and is_nil(changes) and empty?(data) do
        add_error(changeset, field, "can't be blank", validation: :required)
      else
        %Changeset{} = nested_changeset = on_cast.(data || %{}, changes || %{})
        {changeset, original_type} = inject_embedded_changeset(changeset, field, nested_changeset)
        prepare_changes(changeset, &dump(&1, field, original_type))
      end
    end
  end

  def inject_embedded_changeset(changeset, field, nested_changeset) do
    original_type = Map.get(changeset.types, field)

    embedded_type =
      {:embed,
       %Ecto.Embedded{
         cardinality: :one,
         field: field,
         on_cast: nil,
         on_replace: :update,
         owner: %{},
         related: Map.get(changeset.data, :__struct__),
         unique: true
       }}

    nested_changeset = %{nested_changeset | action: changeset.action || :update}

    changeset = %{
      changeset
      | types: Map.put(changeset.types, field, embedded_type),
        valid?: changeset.valid? and nested_changeset.valid?,
        changes: Map.put(changeset.changes, field, nested_changeset)
    }

    {changeset, original_type}
  end

  defp field_invalid?(%Ecto.Changeset{} = changeset, field) do
    Keyword.has_key?(changeset.errors, field)
  end

  defp empty?(term), do: is_nil(term) or term == %{}

  defp dump(changeset, field, original_type) do
    map =
      changeset
      |> get_change(field)
      |> apply_action!(:dump)
      |> Ecto.embedded_dump(:json)
      |> atom_keys_to_string()

    changeset = %{changeset | types: Map.put(changeset.types, field, original_type)}

    put_change(changeset, field, map)
  end

  # We dump atoms to strings because if we persist to Postgres and read it,
  # the map will be returned with string keys, and we want to make sure that
  # the map handling is unified across the codebase.
  defp atom_keys_to_string(map) do
    for {k, v} <- map, into: %{}, do: {to_string(k), v}
  end
end
