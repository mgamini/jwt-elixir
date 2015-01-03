defmodule JWT.Mixfile do
  use Mix.Project

  def project do
    [app: :jwt,
    version: "0.0.2",
    elixir: "~> 1.0.0-rc1",
    deps: deps]
  end

  # Configuration for the OTP application
  def application do
    [applications: [:asn1, :crypto, :public_key]]
  end

  defp deps do
    [{:poison, "~> 1.2.0"}]
  end
end
