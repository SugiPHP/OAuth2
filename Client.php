<?php
/**
 * @package    SugiPHP
 * @subpackage OAuth2
 * @author     Plamen Popov <tzappa@gmail.com>
 * @license    http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\OAuth2;

class Client
{
	/**
	 * Storage for configuration settings
	 * @var array
	 */
	protected $config = array();

	/**
	 * Creates an OAuth2 instance.
	 *
	 * @param array $config - Associative array:
	 * - client_id string REQUIRED
	 * - client_secret string - REQUIRED for Confidential clients, OPTIONAL for Public
	 * - redirect_uri string REQUIRED - default client redirect URI
	 * - auth_endpoint string REQUIRED - Full URI for fetching an auth code e.g. "https://accounts.google.com/o/oauth2/auth" or "https://graph.facebook.com/oauth/authorize"
	 * - token_endpoint string REQUIRED - Full URI for token e.g. "https://accounts.google.com/o/oauth2/token" or "https://graph.facebook.com/oauth/access_token"
	 * - resource_endpoint string REQUIRED - Full URI for resources e.g. "https://www.googleapis.com/oauth2/v1/userinfo" or "https://graph.facebook.com/me"
	 */
	public function __construct(array $config)
	{
		// Default configuration options
		$this->config = array(
			"client_id"         => "",
			"client_secret"     => "",
			"redirect_uri"      => "",
			"auth_endpoint"     => "",
			"token_endpoint"    => "",
			"resource_endpoint" => "",
			"auto_set_state"    => true,
			"use_sessions"      => true,
		);

		// Override default options
		foreach ($config as $name => $value) {
			$this->config[$name] = $value;
		}
	}

	/**
	 * Return server's authentification endpoint URI
	 * 
	 * @param array $params - additional parameters to add in the URI e.g. state
	 * @return string
	 */
	public function getAuthURI(array $params = array())
	{
		$params = array_merge(array(
			"response_type"  => "code",
			"client_id"      => $this->config["client_id"],
			"redirect_uri"   => $this->config["redirect_uri"]
		), $params);

		// If we want to set state automatically
		if (empty($params["state"]) and $this->config["auto_set_state"]) {
			// TODO: what if "use_sessions" is off ???
			$params["state"] = $this->setState();
		}

		return $this->config["auth_endpoint"] . "?" . http_build_query($params, null, "&");
	}

	public function getToken(array $params = null)
	{
		// default params are from $_GET;
		if (is_null($params)) $params = $_GET;

		// Get token in exchange of code
		if (!empty($params["code"])) {
			// check the state. If the state is missing or invalid Exception will be thrown
			if ($this->config["auto_set_state"]) $this->checkState($params);

			$request = array(
				"grant_type" => "authorization_code",
				"code"       => $params["code"],
			);
			if (!empty($params["redirect_uri"])) {
				$request["redirect_uri"] = $params["redirect_uri"];
			} elseif (!empty($this->config["redirect_uri"])) {
				$request["redirect_uri"] = $this->config["redirect_uri"];
			}
		}
		// Get token in exchange of refresh_token
		elseif (!empty($params["refresh_token"])) {
			$request = array(
				"grant_type"    => "refresh_token",
				"refresh_token" => $params["refresh_token"],
			);
		}
		elseif (isset($params["username"], $params["password"])) {
			$request = array(
				"grant_type" => "password",
				"username"   => $params["username"],
				"password"   => $params["password"],
			);
		}
		else {
			throw new Exception("unknown grant type");
		}

		$headers = array(
			"Authorization" => "Basic " . base64_encode($this->config["client_id"] . ":" . $this->config["client_secret"]),
		);
		$result = $this->curlRequest($this->config["token_endpoint"], "POST", $request, $headers, "application/x-www-form-urlencoded");

		if (isset($result["error"])) {
			throw new Exception($result["error"], isset($result["error_description"]) ? $result["error_description"] : null);
		}

		if ($this->config["use_sessions"]) {
			$this->saveSession($result);
		}

		return $result;
	}

	public function api($uri = null, array $params = null)
	{
		if (empty($uri) and !$uri = $this->config["resource_endpoint"]) {
			throw new Exception("Required resource URI is missing");
		}

		if (is_null($params) and $this->config["use_sessions"] and $session = $this->getSession()) {
			$params = ($session["token_expires"] > time()) ? $session : $this->getToken($session);// new token
		}

		if (empty($params["access_token"])) {
			throw new Exception("Access token is missing");
		}
		if (empty($params["token_type"])) {
			throw new Exception("Token type is missing");
		}
		if ($params["token_type"] != "bearer") {
			throw new Exception("Unsupported token type");
		}

		$headers["Authorization"] = "Bearer " . $params["access_token"];

		$result = $this->curlRequest($uri, "POST", null, $headers);

		// try to generate a new token based on refresh token
		if (!empty($result["error"]) and $result["error"] == "invalid_token" and $this->config["use_sessions"] and $session = $this->getSession()) {
			// new token
			$token = $this->getToken($session);
			$headers["Authorization"] = "Bearer " . $token["access_token"];
			$result = $this->curlRequest($uri, "POST", null, $headers);
		}

		if (isset($result["error"])) {
			throw new Exception($result["error"], isset($result["error_description"]) ? $result["error_description"] : null);
		}

		return $result;
	}

	public function getSession()
	{
		$sessionName = $this->getSessionName();
		return empty($_SESSION[$sessionName]) ? null : $_SESSION[$sessionName];
	}

	/**
	 * Sends a cURL request to the OAuth2 Server
	 *
	 * @param string $uri REQUIRED
	 * @param string $method - HTTP method to use, defaults to GET
	 * @param mixed $params - Associative array or url encoded string
	 * @param array $headers - extra HTTP headers to include in request
	 * @param string $encode - HTTP form content type to use on request
	 * @return mixed
	 */
	protected function curlRequest($uri, $method = "GET", $params = null, array $headers = null, $encode = null)
	{
		$curl_options = array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_CUSTOMREQUEST  => $method,
			// TODO: if we are using certificates this should be changed to true
			CURLOPT_SSL_VERIFYPEER => false,
			CURLOPT_SSL_VERIFYHOST => false,
			CURLOPT_HEADER         => true, // we need the result header
		);

		if ($method == "POST") {
			$curl_options[CURLOPT_POST] = true;
		}
		if ($method == "POST" or $method == "PUT") {
			if (is_array($params) and !is_null($encode) and $encode == "application/x-www-form-urlencoded") {
				$params = http_build_query($params);
			}
			$curl_options[CURLOPT_POSTFIELDS] = $params;
		}
		if ($method == "GET" or $method == "HEAD" or $method == "DELETE") {
			if (!is_null($params)) {
				if (is_array($params)) $params = http_build_query($params, null, "&");
				$uri .= "?" . $params;
			}
		}
		if ($method == "HEAD") {
			$curl_options[CURLOPT_NOBODY] = true;
		}

		// extra headers to include
		if (is_array($headers)) {
			$header = array();
			foreach($headers as $key => $parsed_urlvalue) {
				$header[] = "$key: $parsed_urlvalue";
			}
			$curl_options[CURLOPT_HTTPHEADER] = $header;
		}

		// set cURL
		$ch = curl_init($uri);
		curl_setopt_array($ch, $curl_options);

		// execute
		$result = curl_exec($ch);

		// splitting result to header and body
		$resultA = explode("\r\n\r\n", $result, 2);
		$result_header = isset($resultA[0]) ? $resultA[0] : "";
		$result_body = isset($resultA[1]) ? $resultA[1] : "";

		// get response codes, etc.
		$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		$content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
		if ($curl_error = curl_error($ch)) {
			return array("error" => "curl_error", "error_description" => $curl_error);
		}

		// Errors ?
		if ($http_code >= 400) {
			// the error is not in the body. We'll search it in the header
			if (!$result_body and preg_match('#error="([a-z_]+)"#i', $result_header, $matches)) {
				$error = $matches[1];
				$error_description = "";
				if (preg_match('#error_description="(^")+"#i', $result_header, $matches)) {
					$error_description = $matches[1];	
				}
				return array("error" => $error, "error_description" => $error_description);
			}
		}

		// is it JSON?
		if (!is_null($json = json_decode($result_body, true))) $result_body = $json;
		
		// free cURL
		curl_close($ch);
		return $result_body;
	}

	protected function setState()
	{
		$state = md5(uniqid());
		$_SESSION["state"] = $state;

		return $state;
	}

	protected function checkState($params)
	{
		if (empty($params["state"]) or empty($_SESSION["state"]) or ($params["state"] != $_SESSION["state"])) {
			throw new Exception("State parameter is missing or invalid");
		}
		// unset($_SESSION["state"]);

		return true;
	}

	protected function saveSession($params)
	{
		if (isset($params["expires_in"])) {
			$params["token_expires"] = strtotime("+{$params["expires_in"]} seconds");
		}
		$old = $this->getSession();
		if (!empty($old) and is_array($old)) {
			$params = array_merge($old, $params);
		}
		$_SESSION[$this->getSessionName()] = $params;
	}

	protected function getSessionName()
	{
		return md5($this->config["auth_endpoint"]);
	}
}
