defmodule JWT.Mixfile do
  use Mix.Project

  def project do
    [ app: :jwt,
      version: "0.0.1",
      elixir: "~> 0.12.4",
      deps: deps ]
  end

  # Configuration for the OTP application
  def application do
    [:asn1, :crypto, :public_key]
  end

  # Returns the list of dependencies in the format:
  # { :foobar, git: "https://github.com/elixir-lang/foobar.git", tag: "0.1" }
  #
  # To specify particular versions, regardless of the tag, do:
  # { :barbat, "~> 0.1", github: "elixir-lang/barbat" }
  defp deps do
    [ { :jazz, github: "meh/jazz" } ]
  end
end
