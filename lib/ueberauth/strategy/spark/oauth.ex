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
    IO.puts "client!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    IO.inspect opts
    IO.inspect client_opts
    OAuth2.Client.new(client_opts)
  end

  def authorize_url!(params \\ [], opts \\ []) do
    IO.puts "here!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    IO.inspect params
    IO.inspect opts
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  def get_token!(params \\ [], options \\ %{}) do
    headers        = Dict.get(options, :headers, [])
    options        = Dict.get(options, :options, [])
    client_options = Dict.get(options, :client_options, [])
    OAuth2.Client.get_token!(client(client_options), params, headers, options)
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    IO.puts "here!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!222"
    IO.inspect client
    IO.inspect params
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers, [ssl_options: [versions: [:'tlsv1.2']]])
  end
end
