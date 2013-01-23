<?php
/**
 * OAuth2.0 Authorization Server
 * 
 * @package OAuth2
 * @version 13.01.22
 */

require "OAuth2Exception.php";

abstract class OAuth2
{
	/**
	 * Regular expression to verify client ID's
	 * Override this if necessarily
	 * @var string
	 */
	protected $clientIdRegEx = '|^[a-z_0-9]{2,20}$|';

	/**
	 * Regular expression to verify requested scope
	 * TODO: rewrite it!
	 * @var string
	 */
	protected $scopeRegEx = '|^[a-zA-Z_0-9\s]{1,200}$|';

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
			// A list of space-delimited, case-sensitive strings. The order does not matter. 
			// Each string adds an additional access range to the requested scope
			"scopes" 			=> "", 
			// If in the client's request is missing the scope parameter
			// We can either process the request with pre-defined default value (eg. "default_scope" => "basic")
			// or fail the request (set "default_scope" to FALSE or empty string)
			// @see http://tools.ietf.org/html/rfc6749#section-4.1.1
			// @see http://tools.ietf.org/html/rfc6749#section-3.3
			"default_scope" 	=> false,
			// the length (chars) of the codes generated. Anything between 32 and 128. Default is 64.
			"code_size"			=> 64,
			// The lifetime of access token in seconds. Defaults to 1 hour.
			"token_expires_in" 	=> 3600,
			// TODO: add default lifetimes for auth codes, refresh tokens, etc.
		);

		// Override default options
		foreach ($config as $name => $value) {
			$this->config[$name] = $value;
		}
	}

	/**
	 * Authorization Request
	 *  - "response_type" REQUIRED - @see http://tools.ietf.org/html/rfc6749#section-3.1.1
	 *  - "client_id" REQUIRED - @see http://tools.ietf.org/html/rfc6749#section-4.1.1
	 *  - "state" RECOMMENDED
	 *  - "redirect_uri" OPTIONAL
	 *  - "scope" OPTIONAL - @see http://tools.ietf.org/html/rfc6749#section-3.3
	 *
	 * @param array $params - Optional. This is mainly for testing purposes. Defaults to $_GET
	 * @throws OAuth2Exception
	 * @return array - An associative array containing validated parameters passed from the client
	 */
	public function authRequest($params = null)
	{
		if (is_null($params)) $params = $_GET;

		$client_id = empty($params["client_id"]) ? NULL : $params["client_id"];
		$response_type = empty($params["response_type"]) ? NULL : $params["response_type"];
		$state = empty($params["state"]) ? NULL : $params["state"];
		$scope = empty($params["scope"]) ? NULL : $params["scope"];
		$redirect_uri = empty($params["redirect_uri"]) ? NULL : $params["redirect_uri"];

		if (!$response_type) {
			// This check is first, because even if we knew the redirect_uri, we cannot redirect to that uri
			// since we don't know where the error parameter should be - in the query (for "code" auth) or 
			// in the fragment component (for the "token" auth)
			throw new OAuth2Exception("invalid_request", "Response type parameter is required");
		}
		if ($response_type !== "code" AND $response_type !== "token") {
			throw new OAuth2Exception("invalid_request", "Response type parameter is invalid or unsupported");
		}

		// Check client_id is set
		// the RFC does not exclude the use of unregistered clients, but we do
		// @see http://tools.ietf.org/html/rfc6749#section-2.4
		if (!$client_id) {
			throw new OAuth2Exception("invalid_request", "Client ID parameter is required");
		}
		// verify client_id with some regular expression
 		if (!preg_match($this->clientIdRegEx, $client_id)) {
			throw new OAuth2Exception("invalid_request", "Client ID is malformed");
		}
		// get client_id details from some storage (DB)
		$client = $this->getClient($client_id);
		if (!$client) {
			throw new OAuth2Exception("unauthorized_client", "Client does not exist");
		}

		// check redirect_uri is the same as stored in the DB for the client
		if ($redirect_uri and $client["redirect_uri"] and $redirect_uri != $client["redirect_uri"]) {
			throw new OAuth2Exception("access_denied", "Redirect URI does not match");
		}
		// if redirect_uri was not set we'll use registered one
		if (!$redirect_uri) {
			$redirect_uri = $client["redirect_uri"];
		}

		// TODO: check for per-client response_type restrictions
		// Public clients doesn't need "code"
		// Confidetial clients may be restricted to use "token" (implicit grant type)
		// @see http://tools.ietf.org/html/rfc6749#section-3.1.2.2

		// After this point we should navigate (redirect) the end-user to the redirect_uri on errors

		// verify scope with some regular expression
		if ($scope and !preg_match($this->scopeRegEx, $scope)) {
			$this->redirectWithError($response_type, $redirect_uri, "invalid_scope", "The requested scope is invalid or malformed", $state);
		}
		// check the scope is supported
		if ($scope and !$this->checkScope($scope)) {
			$this->redirectWithError($response_type, $redirect_uri, "invalid_scope", "The requested scope is invalid or unknown", $state);
		}
		// check if requested scope MUST be set
		if (!$scope and empty($this->config["default_scope"])) {
			$this->redirectWithError($response_type, $redirect_uri, "invalid_scope", "The scope is mandatory", $state);
		}

		// TODO: check for per-client scope restrictions

		// if in the request scope was not set we can fail back to the default scope
		if (!$scope) {
			$scope = $this->config["default_scope"];
		}

		return array(
			"response_type" 	=> $response_type,
			"client_id" 		=> $client_id,
			"redirect_uri"		=> $redirect_uri,
			"state"				=> $state,
			"scope"				=> $scope
		);
	}

	/**
	 * User Accepts the request
	 * 
	 * @param mixed $user_id
	 */
	public function grantAccess($user_id)
	{
		$request = $this->authRequest();

		// auth code
		if ($request["response_type"] == "code") {
			$code = $this->genCode();
			// save the auth code in some storage (DB)
			$this->saveAuthCode($user_id, $request["client_id"], $code);

			$params = array(
				"code" 	=> $code, 
				"state" => $request["state"]
			);
			$location = $this->rebuildUri($request["redirect_uri"], $params, array());
			$this->redirect($location);
		}
		
		// implicit grant type
		// @see http://tools.ietf.org/html/rfc6749#section-4.2
		if ($request["response_type"] == "token") {
			$access_token = $this->genCode();
			$expires_in = $this->config["token_expires_in"];

			// save token in some storage (DB)
			$this->saveToken($user_id, $request["client_id"], $access_token, strtotime("+$expires_in seconds"));

			$params = array(
				"access_token"	=> $access_token,
				"token_type"	=> "bearer",
				"expires_in" 	=> $expires_in,
				"scope"			=> $request["scope"],
				"state"			=> $request["state"],
			);
			$location = $this->rebuildUri($request["redirect_uri"], array(), $params);
			$this->redirect($location);
		}
	}

	/**
	 * User denies access
	 */
	public function denyAccess()
	{
		$request = $this->authRequest();
		$this->redirectWithError($request["response_type"], $request["redirect_uri"], "access_denied", "The user denied request", $request["state"]);
	}

	/**
	 * Checks the scope is a subset of all supported scopes
	 *
	 * @param string
	 * @return boolean
	 */
	protected function checkScope($scope)
	{
		$scope = explode(" ", $scope);
		$scopes = explode(" ", $this->config["scopes"]);

		return (count(array_diff($scope, $scopes)) == 0);
	}

	/**
	 * Sends http header to redirect user-agent to a specific location and exits the script!
	 * 
	 * @param string $location
	 * @param string $code - Optional
	 */
	protected function redirect($location, $code = "302 Found")
	{
		header("HTTP/1.1 $code");
		header("Location: $location");
		exit;
	}

	/**
	 * TODO: this needs rewrite
	 */
	protected function redirectWithError($response_type, $redirect_uri, $error, $error_description, $state)
	{
		$params = array("error" => $error);
		if ($error_description) $params["error_description"] = $error_description;
		if ($state) $params["state"] = $state;
		if ($response_type == "token") {
			$location = $this->rebuildUri($redirect_uri, array(), $params);
		}
		else {
			$location = $this->rebuildUri($redirect_uri, $params, array());
		}
		$this->redirect($location);
	}

	/**
	 * Rebuilds absolute URI based on supplied URI and additional parameters
	 *
	 * @param string $uri - An absolute URI (redirect_uri)
	 * @param array $queries - An associative array to be appended as GET parameters to the URI
	 * @param array $fragments - An associative array to be appended as GET parameters to the fragment part of the URI
	 * @return string
	 */
	private function rebuildUri($uri, array $queries, array $fragments)
	{
		$parse_url = parse_url($uri);

		// query part of the uri
		$query = $this->rebuildQuery(empty($parse_url["query"]) ? "" : $parse_url["query"], $queries);

		// fragment part of the uri
		$fragment = $this->rebuildQuery(array(), $fragments);

		return (empty($parse_url["scheme"]) ? "" : $parse_url["scheme"] . "://")
			.(empty($parse_url["user"]) ? "" : $parse_url["user"] . (empty($parse_url["pass"]) ? "" : ":" . $parse_url["pass"]) . "@")
			.(empty($parse_url["host"]) ? "" : $parse_url["host"])
			.(empty($parse_url["port"]) ? "" : ":" . $parse_url["port"])
			.(empty($parse_url["path"]) ? "" : $parse_url["path"])
			.(empty($query) ? "" : "?$query")
			.(empty($fragment) ? "" : "#$fragment");
	}

	/**
	 * Rebuilds the query part of the URI with provided query string and additional params
	 * 
	 * @param string $query
	 * @param array $params
	 * @return string
	 */
	protected function rebuildQuery($query, $params)
	{
		$parse_query = array();
		if ($query) {
			$query = explode("&",  $query);
			foreach ($query as $param) {
				$item = explode("=", $param);
				$parse_query[$item[0]] = $item[1];
			}
		}
		return http_build_query(array_merge($parse_query, $params));
	}

	/**
	 * Generates a code
	 *
	 * @return string - Unique code
	 */
	protected function genCode()
	{
		$code = mt_rand() . uniqid(mt_rand(), true) . microtime(true) . mt_rand();

		// SHA-512 produces 128 chars - we can extract only some
		$len = $this->config["code_size"];
		return substr(hash('sha512', $code), mt_rand(0, 128 - $len), $len);
	}

	/**
	 * Reads client details from storage like DB
	 * Client SHOULD be previously be registered on the oauth2 server
	 * @see http://tools.ietf.org/html/rfc6749#section-3.1.2.2
	 * 
	 * @param string $client_id - unique client ID
	 * @return array|NULL - An associative array:
	 *  - redirect_uri string - registered redirect URI
	 *  - client_type - "public" or "confidential"
	 */
	abstract protected function getClient($client_id);


	/**
	 * Saves authorization request code. Based on this code the client will ask for access token.
	 * 
	 * @param $user_id - the value passed in OAuth::grantAccess() method
	 * @param string $client_id
	 * @param string $code
	 */
	abstract protected function saveAuthCode($user_id, $client_id, $code);

	abstract protected function saveToken($user_id, $client_id, $token, $expires);
}
