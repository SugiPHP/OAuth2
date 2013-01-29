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
	 * @see http://tools.ietf.org/html/rfc6749#section-2.2
	 * @var string
	 */
	protected $clientIdRegEx = '#^[a-z_0-9]{2,32}$#';

	/**
	 * Regular expression for client type
	 * @see http://tools.ietf.org/html/rfc6749#section-2.1
	 * @var string
	 */
	protected $clientTypeRegEx = '#^(public|confidential)$#';

	/**
	 * Regular expression to verify requested scope
	 * @var string
	 */
	protected $scopeRegEx = '#^[a-zA-Z_0-9]{2,16}(\s+[a-zA-Z_0-9]{2,16})*$#';

	/**
	 * Regular expression to check authorization code.
	 * @var string
	 */
	protected $codeRegEx = '';

	/**
	 * Storage for configuration settings
	 * @var array
	 */
	protected $config = array();

	/**
	 * Storage for filtered data that was requested or has been created by the OAuth2 class
	 * @var array
	 */
	protected $data = array();

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

		// regular expression for codes based on sha512 and the length of the codes
		$this->codeRegEx = '#^[0-9a-f]{' . $this->config["code_size"] . '}$#';
	}

	/**
	 * Setter for all filtered request parameters or parameters issued by the OAuth2 class
	 */
	public function __set($name, $value)
	{
		$this->data[$name] = $value;
	}

	/**
	 * Getter for all filtered request parameters or parameters issued by the OAuth2 class
	 */
	public function __get($name)
	{
		return isset($this->data[$name]) ? $this->data[$name] : null;
	}

	/**
	 * Handles an exception thrown by this class, typically by printing JSON encoded errors, or by redirecting user-agent to 
	 * a specific location with error messages as a query parameter or in fragment components of the URI
	 * 
	 * @param OAuth2Exception $e
	 */
	public function handleException(OAuth2Exception $e)
	{
		if (!$this->redirect_uri) {
			echo $e;
		}
		else {
			$params = array("error" => $e->getMessage(), "error_description" => $e->error_description, "state" => $this->state);
			if ($this->response_type == "token") {
				$location = $this->rebuildUri($this->redirect_uri, array(), $params);
			}
			else {
				$location = $this->rebuildUri($this->redirect_uri, $params, array());
			}
			$this->redirect($location);
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
	 * @throws OAuth2Exception
	 * @param array $params - GET or POST request
	 * @return array - An associative array containing validated parameters passed from the client
	 */
	public function authRequest(array $params = null)
	{
		if (is_null($params)) $params = $_GET;

		$response_type = empty($params["response_type"]) ? NULL : $params["response_type"];
		$client_id = empty($params["client_id"]) ? NULL : $params["client_id"];
		$redirect_uri = empty($params["redirect_uri"]) ? NULL : $params["redirect_uri"];
		$scope = empty($params["scope"]) ? NULL : $params["scope"];
		$state = empty($params["state"]) ? NULL : $params["state"];

		$this->state = $state;

		if (!$response_type) {
			// This check is first, because even if we knew the redirect_uri, we cannot redirect to that uri
			// since we don't know where the error parameter should be - in the query (for "code" auth) or 
			// in the fragment component (for the "token" auth)
			throw new OAuth2Exception("invalid_request", "Required response type parameter is missing");
		}
		if ($response_type !== "code" AND $response_type !== "token") {
			throw new OAuth2Exception("unsupported_response_type", "Response type parameter is invalid or unsupported");
		}

		if ($response_type === "code" AND !$this instanceof IOAuth2Codes) {
			throw new OAuth2Exception("unsupported_response_type", "Authorization code grant type is not supported");
		}

		if ($response_type === "token" AND !$this instanceof IOAuth2Implicit) {
			throw new OAuth2Exception("unsupported_response_type", "Implicit grant type is not supported");
		}
		
		$this->response_type = $response_type;

		// Checks client and receives information about the client. If something is wrong the OAuth2Exception will be thrown
		$client = $this->checkClient($client_id);

		$this->client_id = $client_id;

		// public clients
		// @see http://tools.ietf.org/html/rfc6749#section-3.1.2.2
		if ($client["client_type"] == "public" AND !$redirect_uri) {
			throw new OAuth2Exception("access_denied", "Public clients MUST register their redirection endpoints");
		}
		// confidential client utilizing the implicit grant type
		// @see http://tools.ietf.org/html/rfc6749#section-3.1.2.2
		if ($client["client_type"] == "confidential" AND $response_type == "token" AND !$redirect_uri) {
			throw new OAuth2Exception("access_denied", "Public clients MUST register their redirection endpoints");
		}
		// If the client can register multiple redirection URI's, or to register only part of the URI, 
		// or not to register any redirection URI as specified in the standard
		// @see http://tools.ietf.org/html/rfc6749#section-3.1.2.3
		// you have to implement IOAuth2DynamicURI and check the client redirect URI based on your implementation
		if ($this instanceof IOauth2DynamicURI) {
			if (!$redirect_uri = $this->checkClientURI($redirect_uri, $client)) {
				throw new OAuth2Exception("access_denied", "Dynamic configuration for redirect URI failed");
			}
		}
		// default check if you did not implement IOAuth2DynamicURI is to check full redirect_uri
		// check redirect_uri is the same as stored in the DB for the client
		elseif ($redirect_uri and $client["redirect_uri"] and $redirect_uri != $client["redirect_uri"]) {
			throw new OAuth2Exception("access_denied", "Redirect URI does not match");
		}
		
		// if redirect_uri was not set we'll use registered one
		if (!$redirect_uri) {
			$redirect_uri = $client["redirect_uri"];
		}

		$this->redirect_uri = $redirect_uri;

		// After this point we should navigate (redirect) the end-user to the redirect_uri on errors

		// verify scope with some regular expression
		if ($scope and !preg_match($this->scopeRegEx, $scope)) {
			throw new OAuth2Exception("invalid_scope", "The requested scope is invalid or malformed");
		}

		// check the scope is supported
		if ($scope and !$this->checkScope($scope)) {
			throw new OAuth2Exception("invalid_scope", "The requested scope is invalid or unknown");
		}
		// check if requested scope is not set, there is no predefined default scope and thus MUST be set
		if (!$scope and empty($this->config["default_scope"])) {
			throw new OAuth2Exception("invalid_scope", "The scope is mandatory");
		}

		// if in the request scope was not set we can fail back to the default scope
		if (!$scope) {
			$scope = $this->config["default_scope"];
		}

		$this->scope = $scope;

		return array(
			"state" 		=> $state,	
			"response_type" => $response_type,
			"client_id"		=> $client_id,
			"redirect_uri"	=> $redirect_uri,
			"scope"			=> $scope,
		);
	}

	/**
	 * User Accepts the request
	 * 
	 * @param mixed $user_id
	 */
	public function grantAccess($user_id)
	{
		$this->authRequest();

		// auth code
		if ($this->response_type == "code") {
			$this->code = $this->genCode();
			// save the auth code in some storage (DB)
			$this->expires_in = $this->config["code_expires_in"];
			$this->saveAuthCode($user_id, $this->client_id, $this->code, strtotime("+{$this->expires_in} seconds"), $this->redirect_uri, $this->scope);

			$location = $this->rebuildUri($this->redirect_uri, array("code" => $this->code, "state" => $this->state), array());
		}
		
		// implicit grant type
		// @see http://tools.ietf.org/html/rfc6749#section-4.2
		if ($this->response_type == "token") {
			$this->access_token = $this->genCode();
			$this->token_type = "bearer";
			$this->expires_in = $this->config["token_expires_in"];

			// save token in some storage (DB)
			$this->saveToken($this->user_id, $this->client_id, $this->access_token, strtotime("+{$this->expires_in} seconds"), $this->scope);

			$location = $this->rebuildUri($this->redirect_uri, array(), array(
				"access_token"	=> $this->access_token,
				"token_type"	=> $this->token_type,
				"expires_in" 	=> $this->expires_in,
				"scope"			=> $this->scope,
				"state"			=> $this->state,
			));
		}

		$this->redirect($location);
	}

	/**
	 * User denies access
	 */
	public function denyAccess()
	{
		$this->authRequest();

		$this->handleException(new OAuth2Exception("access_denied", "The user denied request"));
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
	public function tokenRequest(array $params = null)
	{
		// this always MUST be $_POST, but for testing purposes we allow anything
		if (is_null($params)) $params = $_POST;

		$grant_type = empty($params["grant_type"]) ? NULL : $params["grant_type"];
		$code = empty($params["code"]) ? NULL : $params["code"];
		$redirect_uri = empty($params["redirect_uri"]) ? NULL : $params["redirect_uri"];

		// $client_id and client_secret are submitted via HTTP Basic authentication headers
		// The authorization server MUST support HTTP Basic authentication scheme for 
		// authenticating clients that were issued a client password. More at:
		// @see http://tools.ietf.org/html/rfc6749#section-4.1.3
		$client_id = empty($_SERVER['PHP_AUTH_USER']) ? NULL : $_SERVER['PHP_AUTH_USER'];
		$client_secret = empty($_SERVER['PHP_AUTH_PW']) ? NULL : $_SERVER['PHP_AUTH_PW'];

		if (!$grant_type) {
			throw new OAuth2Exception("invalid_request", "Required grant type parameter is missing");
		}
		if ($grant_type !== "authorization_code") {
			throw new OAuth2Exception("unsupported_grant_type", "Grant type is invalid or unsupported");
		}

		// Checks client and receives information about the client. In case of error throws OAuth2Exception.
		$client = $this->checkClient($client_id);

		// check client credentials
		if ($this instanceof IOauth2Codes and !$this->checkClientCredentials($client_id, $client_secret)) {
			throw new OAuth2Exception("unauthorized_client", "Client credentials are invalid");
		}
		
		// Check for missing code
		if (!$code) {
			throw new OAuth2Exception("invalid_request", "Required code parameter is missing");
		}
		// Check the code with RegEx
		if (!preg_match($this->codeRegEx, $code)) {
			throw new OAuth2Exception("invalid_request", "Code parameter is invalid");	
		}
		
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
		if ($codeData["redirect_uri"] and ($codeData["redirect_uri"] != $redirect_uri)) {
			throw new OAuth2Exception("invalid_grant", "Redirect URI mismatch");
		}

		// Check for invalidated authorization codes
		// "If an authorization code is used more than once, the authorization server MUST deny the request"
		// @see http://tools.ietf.org/html/rfc6749#section-4.1.2
		if ($old_token = $this->getTokenWithCode($code)) {
			// ".. and SHOULD revoke (when possible) all tokens previously issued based on that authorization code"
			// @see http://tools.ietf.org/html/rfc6749#section-4.1.2
			// it's possible!
			$this->revokeToken($old_token);

			// TODO: revoke refresh tokens based on this code if any
			
			throw new OAuth2Exception("invalid_grant", "Used authorization code");
		}

		// Now we have the authenticated user
		$user_id = $codeData["user_id"];

		$access_token = $this->genCode();
		$expires_in = $this->config["token_expires_in"];

		// save token in some storage (DB)
		$this->saveToken($user_id, $client_id, $access_token, strtotime("+$expires_in seconds"), $this->codeData["scope"], $code);

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
			$this->saveRefreshToken($user_id, $client_id, $refresh_token, strtotime("+$refresh_token_expires_in seconds"));

			$params["refresh_token"] = $refresh_token;
		}

		header("HTTP/1.1 200 OK");
		header("Content-Type: application/json;charset=UTF-8");
		header("Cache-Control: no-store");
		header("Pragma: no-cache");
		echo json_encode($params);
		exit;
	}

	/**
	 * Checks received client_id parameter
	 *
	 * @throws OAuth2Exception
	 * @param string $client_id
	 * @return array - Client's registration information
	 */
	protected function checkClient($client_id)
	{
		// Check client_id is set
		// the RFC does not exclude the use of unregistered clients, but we do
		// @see http://tools.ietf.org/html/rfc6749#section-2.4
		if (!$client_id) {
			throw new OAuth2Exception("invalid_request", "Required client ID parameter is missing");
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
	protected function rebuildUri($uri, array $queries, array $fragments)
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
	 * Generates a hash
	 * This is not a part of the OAuth.
	 *
	 * @param string $secret
	 * @return string
	 */
	public static function cryptSecret($secret)
	{
		return crypt($secret, '$2a$10$' .  substr(sha1(mt_rand()), 0, 22));
	}

	/**
	 * Compares a secret against a hash
	 * This is not a part of the OAuth.
	 *
	 * @param string $hash - secret hash made with cryptSecret() method
	 * @param string $secret - secret
	 * @return boolean
	 */
	public static function checkSecret($hash, $secret)
	{
		return ($hash === crypt($secret, substr($hash, 0, 29)));
	}
}
