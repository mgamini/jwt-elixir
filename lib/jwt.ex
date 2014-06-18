defmodule JWT do
  use Jazz

  alias JWT.Headers
  alias JWT.Base64
  alias JWT.EncodeError
  alias JWT.DecodeError


  @plaintext_algorithms ["none"]
  @hmac_algorithms      ~W[HS256 HS384 HS512]
  @rsa_algorithms       ~W[RS256 RS384 RS512]
  @supported_algorithms @plaintext_algorithms ++ @hmac_algorithms ++ @rsa_algorithms

  def encode(payload) do
    encode(payload, nil, "none")
  end

  def encode(payload, key, algorithm \\ "HS256", headers \\ %{}) do
    unless algorithm in @supported_algorithms do
      raise EncodeError, message: "unsupported algorithm: #{algorithm}"
    end

    headers = encode_part(Headers.headers(algorithm, headers), "header")
    payload = encode_part(payload, "payload")

    message   = headers <> "." <> payload
    signature = sign(algorithm, message, key)
    message <> "." <> signature
  end


  def sign(algorithm, _, _ ) when algorithm in @plaintext_algorithms, do: ""

  def sign(algorithm, message, key) when algorithm in @rsa_algorithms do
    key =
      key
      |> :public_key.pem_decode
      |> hd
      |> :public_key.pem_entry_decode

    Base64.encode(:public_key.sign(message, digest_type(algorithm), key))
  end

  def sign(algorithm, message, key) when algorithm in @hmac_algorithms do
    algorithm
    |> String.replace("HS", "sha")
    |> binary_to_atom
    |> :crypto.hmac(key, message)
    |> Base64.encode
  end

  def decode(message, key, algorithm \\ "HS256", opts \\ []) do
    { header, payload, signature } =
      case String.split(message, ".") do
        [ header, payload, signature ] ->
          { header, payload, signature }
        _other ->
          raise DecodeError, message: "invalid payload"
      end

    signing_input = header <> "." <> payload
    header  = decode_part(header, "header")
    payload = decode_part(payload, "payload")

    if opts[:verify] do
      algorithm = header[:alg]
      verify_signature(algorithm, signing_input, key, signature)
      payload
    else
      payload
    end
  end

  def verify_signature(alg, _, _, "") do
    alg in @plaintext_algorithms
  end

  def verify_signature(alg, signing_input, key, signature) when alg in @rsa_algorithms do
    :public_key.verify(signing_input, digest_type(alg), signature, key)
  end

  def verify_signature(alg, signing_input, key, signature) when alg in @hmac_algorithms do
    signature == sign(alg, signing_input, key)
  end

  def supported_algorithms, do: @supported_algorithms
  def hmac_algorithms, do: @hmac_algorithms
  def rsa_algorithms, do: @rsa_algorithms

  defp encode_part(part, name) do
    case JSON.encode(part) do
      { :ok, json } -> Base64.encode(json)
      { :error, _ } -> raise EncodeError, message: "invalid #{name}"
    end
  end

  defp decode_part(part, name) do
    case JSON.decode(Base64.decode(part)) do
      { :ok, json } -> json
      { :error, error } -> raise DecodeError, message: "invalid #{name}: #{error}"
    end
  end

  digest_algorithms = @rsa_algorithms ++ @hmac_algorithms

  digest_types = Enum.map digest_algorithms, fn algorithm ->
    digest_type =
      algorithm
        |> String.replace(~r/(R|H)S/, "sha")
        |> binary_to_atom
    { algorithm, digest_type }
  end

  Enum.map digest_types, fn { alg, digest_type } ->
    defp(digest_type(unquote(alg)), do: unquote(digest_type))
  end
end

defmodule JWT.Headers do
  @disallowed [:alg, "alg", :typ, "typ"]

  def clean(headers) do
    Dict.drop(headers, @disallowed)
  end

  def headers(alg, headers \\ %{}) do
     Dict.merge(%{typ: "JWT", alg: alg}, clean(headers))
  end
end

defmodule JWT.Base64 do
  def encode(binary) when is_binary(binary) do
    :base64.encode(binary) |> String.replace("=", "")
  end

  def decode(encoded) do
    :base64.decode(pad(encoded))
  end

  def pad(string) do
    case rem(size(string), 4) do
      0 -> string
      _ -> pad(string <> "=")
    end
  end
end

defmodule JWT.EncodeError do
  defexception [:message]
end

defmodule JWT.DecodeError do
  defexception [:message]
end
