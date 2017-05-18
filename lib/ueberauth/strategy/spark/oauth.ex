defmodule Ueberauth.Strategy.Spark.OAuth do
  @moduledoc false
  use OAuth2.Strategy

  @defaults [
    strategy: __MODULE__,
    site: "https://developer.ciscospark.com",
    authorize_url: "https://api.ciscospark.com/v1/authorize",
    token_url: "https://api.ciscospark.com/v1/access_token"
  ]

  def client(opts \\ []) do
    spark_config = Application.get_env(:ueberauth, Ueberauth.Strategy.Spark.OAuth)
    client_opts =
      @defaults
      |> Keyword.merge(spark_config)
      |> Keyword.merge(opts)
    IO.inspect @defaults
    OAuth2.Client.new(client_opts)
  end

  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  def get_token!(params \\ [], options \\ %{}) do
    headers        = Dict.get(options, :headers, [])
    options        = Dict.get(options, :options, [])
    client_options = Dict.get(options, :client_options, [])
    OAuth2.Client.get_token!(client(client_options), params, headers, options ++ [hackney: [ssl_options: [versions: [:'tlsv1.2']]]])
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end
end
