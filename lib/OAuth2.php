<?php
/**
 * OAuth2.0 Authorization Server
 * 
 * @package OAuth2
 */

require "OAuth2Exception.php";

class OAuth2
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
	 * Creates an OAuth2 instance.
	 * Implementor of the OAuth2 server cannot use this class directly.
	 *
	 * @param array $config
	 */
	protected function __construct(array $config = array())
	{
		if (!$this instanceof IOAuth2Tokens) {
			throw new \Exception("To use OAuth2 you must first implement IOAuth2Tokens");
		}

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
			// The lifetime of the auth code in seconds. Defaults to 30 seconds.
			"code_expires_in"	=> 30,
			// The lifetime of access token in seconds. Defaults to 1 hour.
			"token_expires_in" 	=> 3600,
			// The lifetime of refresh token in seconds. Defaults to 30 days
			"refresh_token_expires_in"	=> 2592000, 
		);

		// Override default options
		foreach ($config as $name => $value) {
			$this->config[$name] = $value;
		}
	}

	/**
	 * Keeping this method simple as possible, so it can be easily overridden
	 */
	public function authRequest()
	{
		$request = $this->validateAuthRequest($_GET);
		
		// Custom implementations can do some additional checks:
		// Check for per-client response_type restrictions. Public clients doesn't need "code" and 
		// confidential clients might be restricted to use "token" (implicit grant type)
		// @see http://tools.ietf.org/html/rfc6749#section-3.1.2.2
		// 
		// and check for per-client scope restrictions

		extract($request);

		if (!empty($error)) {
			if (empty($redirect_uri)) {
				echo json_encode($request);
				exit;
			}

			if ($response_type == "code") {
				$location = $this->rebuildUri($redirect_uri, array("error" => $error, "error_description" => $error_description, "state" => $state), array());
			}
			else {
				$location = $this->rebuildUri($redirect_uri, array(), array("error" => $error, "error_description" => $error_description, "state" => $state));
			}
			$this->redirect($location);
		}

		return $request;
	}

	public function denyAccess()
	{
		$result = $this->createDenyAccess();
		extract($result);

		if ($response_type == "code") {
			$location = $this->rebuildUri($redirect_uri, array("error" => $error, "error_description" => $error_description, "state" => $state), array());
		}
		else {
			$location = $this->rebuildUri($redirect_uri, array(), array("error" => $error, "error_description" => $error_description, "state" => $state));
		}

		$this->redirect($location);
	}

	public function grantAccess($user_id)
	{
		$result = $this->createGrantAccess($user_id);
		extract($result);

		if ($response_type == "code") {
			$location = $this->rebuildUri($redirect_uri, array("code" => $code, "state" => $state), array());
		}
		else {
			$location = $this->rebuildUri($redirect_uri, array(), array(
				"access_token"	=> $access_token,
				"token_type"	=> $token_type,
				"expires_in" 	=> $expires_in,
				"scope"			=> $scope,
				"state"			=> $state,
			));
		}
		$this->redirect($location);
	}

	/**
	 * Authorization Request
	 *  - "response_type" REQUIRED - @see http://tools.ietf.org/html/rfc6749#section-3.1.1
	 *  - "client_id" REQUIRED - @see http://tools.ietf.org/html/rfc6749#section-4.1.1
	 *  - "state" RECOMMENDED
	 *  - "redirect_uri" OPTIONAL
	 *  - "scope" OPTIONAL - @see http://tools.ietf.org/html/rfc6749#section-3.3
	 *
	 * @param array $params - GET or POST request
	 * @return array - An associative array containing validated parameters passed from the client
	 */
	protected function validateAuthRequest($params)
	{
		$response_type = empty($params["response_type"]) ? NULL : $params["response_type"];
		$client_id = empty($params["client_id"]) ? NULL : $params["client_id"];
		$redirect_uri = empty($params["redirect_uri"]) ? NULL : $params["redirect_uri"];
		$scope = empty($params["scope"]) ? NULL : $params["scope"];
		$state = empty($params["state"]) ? NULL : $params["state"];

		// Filtered request
		$request = array();
		// nothing to check for state
		$request["state"] = $state;

		if (!$response_type) {
			// This check is first, because even if we knew the redirect_uri, we cannot redirect to that uri
			// since we don't know where the error parameter should be - in the query (for "code" auth) or 
			// in the fragment component (for the "token" auth)
			return array("error" => "invalid_request", "error_description" => "Required response type parameter is missing");
		}
		if ($response_type !== "code" AND $response_type !== "token") {
			return array("error" => "unsupported_response_type", "error_description" => "Response type parameter is invalid or unsupported");
		}

		$request["response_type"] = $response_type;

		if ($response_type === "code" AND !$this instanceof IOAuth2Codes) {
			return array("error" => "unsupported_response_type", "error_description" => "Response type is not supported");
		}

		// Checks client and receives information about the client
		$client = $this->checkClient($client_id);
		if (!empty($client["error"])) {
			return $client;
		}

		$request["client_id"] = $client_id;

		// check redirect_uri is the same as stored in the DB for the client
		if ($redirect_uri and $client["redirect_uri"] and $redirect_uri != $client["redirect_uri"]) {
			return array("error" => "access_denied", "error_description" => "Redirect URI does not match");
		}
		// if redirect_uri was not set we'll use registered one
		if (!$redirect_uri) {
			$redirect_uri = $client["redirect_uri"];
		}

		$request["redirect_uri"] = $redirect_uri;

		// After this point we should navigate (redirect) the end-user to the redirect_uri on errors

		// verify scope with some regular expression
		if ($scope and !preg_match($this->scopeRegEx, $scope)) {
			return array_merge($request, array("error" => "invalid_scope", "error_description" => "The requested scope is invalid or malformed"));
		}

		// check the scope is supported
		if ($scope and !$this->checkScope($scope)) {
			return array_merge($request, array("error" => "invalid_scope", "error_description" => "The requested scope is invalid or unknown"));
		}
		// check if requested scope is not set, there is no predefined default scope and thus MUST be set
		if (!$scope and empty($this->config["default_scope"])) {
			return array_merge($request, array("error" => "invalid_scope", "error_description" => "The scope is mandatory"));
		}

		// if in the request scope was not set we can fail back to the default scope
		if (!$scope) {
			$scope = $this->config["default_scope"];
		}

		$request["scope"] = $scope;

		return $request;
	}

	/**
	 * User Accepts the request
	 * 
	 * @param mixed $user_id
	 */
	protected function createGrantAccess($user_id)
	{
		$result = $this->authRequest();

		// auth code
		if ($result["response_type"] == "code") {
			$result["code"] = $this->genCode();
			// save the auth code in some storage (DB)
			$expires_in = $this->config["code_expires_in"];
			$this->saveAuthCode($user_id, $result["client_id"], $result["code"], strtotime("+$expires_in seconds"), $result["redirect_uri"]);
		}
		
		// implicit grant type
		// @see http://tools.ietf.org/html/rfc6749#section-4.2
		if ($result["response_type"] == "token") {
			$result["access_token"] = $this->genCode();
			$result["token_type"] = "bearer";
			$result["expires_in"] = $this->config["token_expires_in"];

			// save token in some storage (DB)
			$this->saveToken($user_id, $result["client_id"], $result["access_token"], strtotime("+{$result['expires_in']} seconds"));
		}

		return $result;
	}

	/**
	 * User denies access
	 */
	public function createDenyAccess()
	{
		$result = $this->authRequest();
		$result["error"] = "access_denied";
		$result["error_description"] = "The user denied request";

		return $result;
	}

	/**
	 * Access Token Request
	 *  - "grant_type" REQUIRED - Value MUST be set to "authorization_code"
	 *  - "code" REQUIRED - Authorization code received from OAuth2::grantAccess() method
	 *  - "client_id" REQUIRED
	 *  - "redirect_uri" REQUIRED
	 * 
	 * @see http://tools.ietf.org/html/rfc6749#section-4.1.3
	 *  
	 * @param array $params - Optional. This is mainly for testing purposes. Defaults to $_POST
	 * @throws OAuth2Exception
	 * @return array - An associative array containing validated parameters passed from the client
	 */
	public function tokenRequest($params = null)
	{
		// this always MUST be $_POST, but for testing purposes we allow anything
		if (is_null($params)) $params = $_POST;

		$grant_type = empty($params["grant_type"]) ? NULL : $params["grant_type"];
		$client_id = empty($params["client_id"]) ? NULL : $params["client_id"];
		$code = empty($params["code"]) ? NULL : $params["code"];
		$redirect_uri = empty($params["redirect_uri"]) ? NULL : $params["redirect_uri"];

		if (!$grant_type) {
			throw new OAuth2Exception("invalid_request", "Required grant type parameter is missing");
		}
		if ($grant_type !== "authorization_code") {
			throw new OAuth2Exception("unsupported_grant_type", "Grant type is invalid or unsupported");	
		}

		// Checks client and receives information about the client. In case of error throws OAuth2Exception.
		$client = $this->checkClient($client_id);

		// TODO: check client credentials

		// Check the code
		if (!$code) {
			throw new OAuth2Exception("invalid_request", "Required code parameter is missing");
		}

		// TODO: Check code with RegEx
		
		// retrieve stored data associated with the code
		$codeData = $this->getAuthCode($code);

		if (!$codeData) {
			throw new OAuth2Exception("invalid_grant", "Invalid code");
		}
		if ($codeData["client_id"] != $client_id) {
			throw new OAuth2Exception("invalid_grant", "Client mismatch");
		}
		if ($codeData["expires"] < time()) {
			throw new OAuth2Exception("invalid_grant", "Code expired");
		}
		if ($codeData["redirect_uri"] and ($codaData["redirect_uri"] != $redirect_uri)) {
			throw new OAuth2Exception("invalid_grant", "Redirect URI mismatch");
		}

		// Now we have the authenticated user
		$user_id = $codeData["user_id"];

		$access_token = $this->genCode();
		$expires_in = $this->config["token_expires_in"];

		// save token in some storage (DB)
		$this->saveToken($user_id, $client_id, $access_token, strtotime("+$expires_in seconds"));

		$params = array(
			"access_token"	=> $access_token,
			"token_type"	=> "bearer",
			"expires_in" 	=> $expires_in,
		);

		// TODO 
		if ($this instanceof IOAuth2RefreshTokens) {
			$refresh_token = $this->genCode();
			$refresh_token_expires_in = $this->config["refresh_token_expires_in"];
			// ???
			$this->saveRefreshToken($user_id, $client_id, $refresh_token, "+$refresh_token_expires_in seconds");

			$params["refresh_token"] = $refresh_token;
		}

		header("HTTP/1.1 200 OK");
		header("Content-Type: application/json;charset=UTF-8");
		header("Cache-Control: no-store");
		header("Pragma: no-cache");
		echo json_encode($params);
	}

	/**
	 * Checks received client_id parameter
	 *
	 * @param string $client_id
	 * @return array - Client's registration information
	 */
	protected function checkClient($client_id)
	{
		// Check client_id is set
		// the RFC does not exclude the use of unregistered clients, but we do
		// @see http://tools.ietf.org/html/rfc6749#section-2.4
		if (!$client_id) {
			return array("error" => "invalid_request", "error_description" => "Required client ID parameter is missing");
		}
		// verify client_id with some regular expression
 		if (!preg_match($this->clientIdRegEx, $client_id)) {
			return array("error" => "invalid_request", "error_description" => "Client ID is malformed");
		}
		// get client_id details from some storage (DB)
		$client = $this->getClient($client_id);
		if (!$client) {
			return array("error" => "unauthorized_client", "error_description" => "Client does not exist");
		}

		return $client;
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
}
