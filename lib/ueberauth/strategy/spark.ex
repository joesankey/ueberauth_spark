defmodule Ueberauth.Strategy.Spark do
  @moduledoc """
  Implements an ÜeberauthSpark strategy for authentication with ciscospark.com.

  When configuring the strategy in the Üeberauth providers, you can specify some defaults.

  * `uid_field` - The field to use as the UID field. This can be any populated field in the info struct. Default `:email`
  * `default_scope` - The scope to request by default from spark (permissions). Default "spark:messages_read"
  * `oauth2_module` - The OAuth2 module to use. Default Ueberauth.Strategy.Spark.OAuth

  ````elixir

  config :ueberauth, Ueberauth,
    providers: [
      spark: { Ueberauth.Strategy.Spark, [uid_field: :id, default_scope: "spark:messages_read,spark:messages_write"] }
    ]
  """
  use Ueberauth.Strategy, uid_field: :id,
                          default_scope: "spark:people_read",
                          oauth2_module: Ueberauth.Strategy.Spark.OAuth

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  # When handling the request just redirect to Slack
  @doc false
  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)
    opts = [scope: scopes]
    opts =
      if conn.params["state"], do: Keyword.put(opts, :state, conn.params["state"]), else: opts

    callback_url = callback_url(conn)
    callback_url =
      if String.ends_with?(callback_url, "?"), do: String.slice(callback_url, 0..-2), else: callback_url

    opts = Keyword.put(opts, :redirect_uri, callback_url)
    module = option(conn, :oauth2_module)

    redirect!(conn, apply(module, :authorize_url!, [opts]))
  end

  # When handling the callback, if there was no errors we need to
  # make two calls. The first, to fetch the spark auth is so that we can get hold of
  # the user id so we can make a query to fetch the user info.
  # So that it is available later to build the auth struct, we put it in the private section of the conn.
  @doc false
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    module  = option(conn, :oauth2_module)
    params  = [code: code]
    options = %{
      options: [
        client_options: [redirect_uri: callback_url(conn)]
      ]
    }
    token = apply(module, :get_token!, [params, options])

    if token.access_token == nil do
      set_errors!(conn, [error(token.other_params["error"], token.other_params["error_description"])])
    else
      conn
      |> store_token(token)
      |> fetch_user(token)
    end
  end

  # If we don't match code, then we have an issue
  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  # We store the token for use later when fetching the slack auth and user and constructing the auth struct.
  @doc false
  defp store_token(conn, token) do
    put_private(conn, :spark_token, token)
  end

  # Remove the temporary storage in the conn for our data. Run after the auth struct has been built.
  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:spark_user, nil)
    |> put_private(:spark_token, nil)
  end

  # The structure of the requests is such that it is difficult to provide cusomization for the uid field.
  # instead, we allow selecting any field from the info struct
  @doc false
  def uid(conn) do
    Map.get(info(conn), option(conn, :uid_field))
  end

  @doc false
  def credentials(conn) do
    token        = conn.private.spark_token
    user         = conn.private.spark_user
    scope_string = (token.other_params["scope"] || "")
    scopes       = String.split(scope_string, ",")

    %Credentials{
      token: token.access_token,
      refresh_token: token.refresh_token,
      expires_at: token.expires_at,
      token_type: token.token_type,
      expires: !!token.expires_at,
      other: %{
        user: user,
        user_id: user["id"]
      }
    }
  end

  @doc false
  def info(conn) do
    user = conn.private.spark_user

    %Info{
      name: name_from_user(user),
      nickname: user["nickName"],
      email: Enum.at(user["emails"], 0)
      }
  end

  @doc false
  def extra(conn) do
    %Extra {
      raw_info: %{
        token: conn.private[:spark_token],
        user: conn.private[:spark_user]
        }
    }
  end

  # If the call to fetch the auth fails, we're going to have failures already in place.
  # If this happens don't try and fetch the user and just let it fail.
  defp fetch_user(%Plug.Conn{assigns: %{ueberauth_failure: _fails}} = conn, _), do: conn

  # Given the auth and token we can now fetch the user.
  defp fetch_user(conn, token) do

    case OAuth2.AccessToken.get(token, "/people/me", [{"Content-Type", "application/json"}]) do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])
      {:ok, %OAuth2.Response{status_code: status_code, body: user}} when status_code in 200..399 ->
          IO.inspect status_code
          IO.inspect user
          put_private(conn, :spark_user, user)
      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  # Fetch the name to use. We try to start with the most specific name avaialble and
  # fallback to the least.
  defp name_from_user(user) do
  user["displayName"]
  end

  defp option(conn, key) do
    Dict.get(options(conn), key, Dict.get(default_options, key))
  end
end
