#!/usr/bin/env escript

%% Generates mix.exs from ebin/mysql.app.
%% The mix file is used for publishing the package to Hex.

-mode(compile).

-define(MIX_TPL,
<<"defmodule Mysql.Mixfile do
  use Mix.Project

  def project() do
    [app: :mysql,
     version: \"~s\",
     elixir: \"~~> 1.0\",
     description: description(),
     package: package(),
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps(),
     aliases: aliases()]
  end

  defp description() do
     \"\"\"
     ~s
     \"\"\"
  end

  defp package() do
    [contributors: [\"Viktor Söderqvist\", \"Jan Uhlig\", \"et.al.\"],
     maintainers: [\"Viktor Söderqvist\", \"TJ\"],
     licenses: [\"LGPL-3.0-or-later\"],
     links: %{\"GitHub\" => \"https://github.com/mysql-otp/mysql-otp\"},
     build_tools: [\"make\", \"rebar3\", \"mix\"],
     files: ~~w(mix.exs README.md CHANGELOG.md) ++
            ~~w(doc erlang.mk include Makefile priv src test)
    ]
  end

  # Configuration for the OTP application
  #
  # Type `mix help compile.app` for more information
  def application() do
    [applications: [:ssl]]
  end

  # Dependencies
  defp deps() do
    []
  end

  # Alias docs to nothing, just to be able to publish docs to Hex
  # using already generated docs
  defp aliases() do
    [
      docs: []
    ]
  end
end
">>).

main(_) ->
    {ok, [{application, mysql, Props}]} =
        file:consult("ebin/mysql.app"),
    Vsn = proplists:get_value(vsn, Props),
    Desc = proplists:get_value(description, Props),
    io:setopts([{encoding, unicode}]),
    io:format(?MIX_TPL, [Vsn, Desc]).
