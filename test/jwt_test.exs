defmodule JWTTest do
  use ExUnit.Case

  @private_key File.read!(Path.join(__DIR__, "id_rsa"))
  @public_key File.read!(Path.join(__DIR__, "id_rsa.pub"))

  alias JWT.Headers
  alias JWT.Base64

  @payload %{"iss" => "joe", "exp" => 1300819380, "http://example.com/is_root" => true}

  test "Headers.clean" do
    assert %{foo: :bar} == Headers.clean(%{
      :alg => "someval", "alg" => "someval",
      :typ => "someval", "typ" => "someval",
      :foo => :bar
    })
  end

  test "Headers.headers" do
    assert %{typ: "JWT", alg: :foo, bar: :baz} == Headers.headers(:foo, bar: :baz, typ: "XXX")
  end

  test "Base64.encode" do
    "AQIDAwQ" = Base64.encode(<<1,2,3,3,4>>)
  end

  test "Base64.decode (without padding)" do
    <<1,2,3,3,4>> = Base64.decode("AQIDAwQ")
  end

  test "encode plain text" do
    assert JWT.encode(@payload)
  end

  test "decode" do
    key = "shhhhhh!"
    Enum.each JWT.hmac_algorithms ++ ["none"], fn (alg) ->
      assert @payload == JWT.decode(JWT.encode(@payload, key, alg), key)
    end
  end

  test "rsa encode" do
    assert @payload == JWT.decode(JWT.encode(@payload, @private_key, "RS256"), @public_key, "RS256")
  end
end
