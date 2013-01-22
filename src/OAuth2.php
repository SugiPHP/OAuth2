<?php
/**
 * OAuth2.0 Authorization Server
 * 
 * @package OAuth2
 * @version 13.01.22
 */


class OAuth2
{
	/**
	 * Storage for configuration settings
	 * @var array
	 */
	protected $config;

	/**
	 * Creates an OAuth2 instance
	 *
	 * @param array $config
	 */
	public function __construct(array $config = array())
	{
		// Default configuration options
		$this->config = array(
			// TODO: add default lifetimes for auth codes, access token, refresh tokens, etc.
		);

		// Override default options
		foreach ($config as $name => $value) {
			$this->config[$name] = $value;
		}
	}

	/**
	 * Authorization Request
	 *  - "response_type" REQUIRED - @see http://tools.ietf.org/html/rfc6749#section-3.1.1
	 * 
	 * 
	 * @return array - An associative array containing validated parameters passed from the client
	 */
	public function authRequest()
	{
		$response_type = empty($_GET["response_type"]) ? NULL : $_GET["response_type"];
		if (!$response_type) {
			// TODO: use custom exception
			throw new \Exception("response_type param is required");
		}
		if ($response_type !== "code" AND $response_type !== "token") {
			throw new \Exception("response_type is invalid");
		}

		return array(
			"response_type" => $response_type,
		);
	}
}
