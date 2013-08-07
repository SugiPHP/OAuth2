<?php
/**
 * Testing with MAC tokens
 *
 * @todo
 */
class Mac
{
	const MAC_ALGORITHM = "HMAC-SHA-256";

	protected $appSecret;

	public function __construct($appSecret)
	{
		$this->appSecret = $appSecret;
	}

	public function signRequest(array $data)
	{
		$data["mac_key"] = md5(mt_rand()); // TODO: make it more random
		// TODO: $data["kid"] = ???
		$data["mac_algorithm"] = self::MAC_ALGORITHM;
		$data["ts"] = time();
		
		$raw = base64_encode(json_encode($data));

		return base64_encode(hash_hmac("sha256", $raw, $this->appSecret, true)).".".$raw;
	}

	public function parseRequest($request)
	{
		list($sig, $raw) = explode(".", $request, 2);

		// decode the data
		$sig = base64_decode($sig);
		$data = json_decode(base64_decode($raw), true);

		if (strtoupper($data["mac_algorithm"]) !== self::MAC_ALGORITHM) {
			throw new \Exception("Unsupported MAC algorithm. Use " . self::MAC_ALGORITHM);
		}

		// check the signature by signing the data with application's secret
		if ($sig !== hash_hmac("sha256", $raw, $this->appSecret, true)) {
			throw new \Exception("Wrong signature!");
		}

		return $data;
	}
}

$mac = new Mac("abc");
$signed_message = $mac->signRequest(
	array(
		"access_token" => "jr5xkCAg4hGcls9FXMVIuQ",
	)
);
echo $signed_message;
var_dump($mac->parseRequest($signed_message));
