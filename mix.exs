defmodule Mysql.Mixfile do
  use Mix.Project

  def project() do
    [app: :mysql,
     version: "1.5.0",
     elixir: "~> 1.0",
     description: description(),
     package: package(),
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps()]
  end

  defp description() do
     """
     MySQL/OTP – MySQL driver for Erlang/OTP
     """
  end

  defp package() do
    [contributors: ["Viktor Söderqvist"],
     maintainers: ["TJ"],
     licenses: ["LGPL v3"],
     links: %{"GitHub" => "https://github.com/mysql-otp/mysql-otp"},
     files: ~w(mix.exs README.md CHANGELOG.md) ++
            ~w(doc erlang.mk include Makefile priv src test)
    ]
  end

  # Configuration for the OTP application
  #
  # Type `mix help compile.app` for more information
  def application() do
    [applications: [:logger]]
  end

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type `mix help deps` for more examples and options
  defp deps() do
    [
      {:ex_doc, ">= 0.0.0", only: :dev}
    ]
  end
end
