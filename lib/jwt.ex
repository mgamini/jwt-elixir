defmodule JWT do
  alias JWT.Headers
  alias JWT.Base64
  alias JWT.EncodeError
  alias JWT.DecodeError


  @plaintext_algorithms ["none"]
  @hmac_algorithms      ~W[HS256 HS384 HS512]
  @supported_algorithms @plaintext_algorithms ++ @hmac_algorithms

  def encode(payload) do
    encode(payload, nil, "none")
  end

  def encode(payload, key, algorithm \\ "HS256", headers \\ []) do
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

  def sign(algorithm, message, key) when algorithm in @hmac_algorithms do
    algorithm
    |> String.replace("HS", "sha")
    |> binary_to_atom
    |> :crypto.hmac(key, message)
    |> Base64.encode
  end


  def decode(payload, key, opts \\ []) do
    { signed?, header, payload, signature } =
      case String.split(payload, ".") do
        [ header, payload, "" ] ->
          { false, header, payload, "" }
        [ header, payload, signature ] ->
          { true, header, payload, signature }
        _other ->
          raise DecodeError, message: "invalid payload"
      end

    header  = decode_part(header, "header")
    payload = decode_part(payload, "payload")

    if signed? do
      decode_signed(header, payload, signature, key, opts)
    else
      decode_unsigned(header, payload)
    end
  end

  def decode_unsigned(header, payload) do
    if header[:alg] in @plaintext_algorithms do
      payload
    else
      raise DecodeError, message: "missing signature"
    end
  end

  def decode_signed(header, payload, signature, key, opts) do
    if opts[:verify] do
      algorithm = header[:alg]
      unless ^signature = sign(algorithm, payload, key) do
        raise DecodeError, message: "invalid signature"
      end
    else
      payload
    end
  end

  def supported_algorithms, do: @supported_algorithms
  def hmac_algorithms, do: @hmac_algorithms

  defp encode_part(part, name) do
    case JSON.encode(part) do
      { :ok, json } -> Base64.encode(json)
      { :error, _ } -> raise EncodeError, message: "invalid #{name}"
    end
  end

  defp decode_part(part, name) do
    case JSON.decode(Base64.decode(part), keys: :atoms!) do
      { :ok, json } -> json
      { :error, error } -> raise DecodeError, message: "invalid #{name}: #{error}"
    end
  end
end

defmodule JWT.Headers do
  @disallowed [:alg, "alg", :typ, "typ"]

  def clean(headers) do
    Dict.drop(headers, @disallowed)
  end

  def headers(alg, headers \\ []) do
     Dict.merge([typ: "JWT", alg: alg], clean(headers))
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

defexception JWT.EncodeError, [:message]
defexception JWT.DecodeError, [:message]
