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
			"scopes" => "", 
			// If in the client's request is missing the scope parameter
			// We can either process the request with pre-defined default value (eg. "default_scope" => "basic")
			// or fail the request (set "default_scope" to FALSE or empty string)
			// @see http://tools.ietf.org/html/rfc6749#section-4.1.1
			// @see http://tools.ietf.org/html/rfc6749#section-3.3
			"default_scope" => false,
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
	 *  - "client_id" REQUIRED - @see http://tools.ietf.org/html/rfc6749#section-4.1.1
	 *  - "state" RECOMMENDED
	 *  - "redirect_uri" OPTIONAL
	 *  - "scope" OPTIONAL - @see http://tools.ietf.org/html/rfc6749#section-3.3
	 * 
	 * @throws OAuth2Exception
	 * @return array - An associative array containing validated parameters passed from the client
	 */
	public function authRequest()
	{
		$client_id = empty($_GET["client_id"]) ? NULL : $_GET["client_id"];
		$response_type = empty($_GET["response_type"]) ? NULL : $_GET["response_type"];
		$state = empty($_GET["state"]) ? NULL : $_GET["state"];
		$scope = empty($_GET["scope"]) ? NULL : $_GET["scope"];
		$redirect_uri = empty($_GET["redirect_uri"]) ? NULL : $_GET["redirect_uri"];

		// Check client_id is set
		// the RFC does not exclude the use of unregistered clients, but we do
		// @see http://tools.ietf.org/html/rfc6749#section-2.4
		if (!$client_id) {
			throw new OAuth2Exception("invalid_request", "Client ID parameter is required");
		}
		// verify client_id with some regular expression
 		if (!preg_match($this->clientIdRegEx, $client_id)) {
			throw new OAuth2Exception("invalid_request", "Client id is malformed");
		}
		// get client_id details from some storage (DB)
		$client = $this->getClient($client_id);
		if (!$client) {
			throw new OAuth2Exception("unauthorized_client", "Client does not exist");
		}

		// check redirect_uri is the same as stored in the DB for the client
		if ($redirect_uri and $client["redirect_uri"] and $redirect_uri != $client["redirect_uri"]) {
			throw new OAuth2Exception("invalid_request", "Redirect URI does not match");
		}
		// if redirect_uri was not set we'll use registered one
		if (!$redirect_uri) {
			$redirect_uri = $client["redirect_uri"];
		}

		// TODO: After this point we should navigate (redirect) the end-user to the redirect_uri
		// instead of throwing exceptions

		if (!$response_type) {
			throw new OAuth2Exception("invalid_request", "Response type parameter is required");
		}
		if ($response_type !== "code" AND $response_type !== "token") {
			throw new OAuth2Exception("unsupported_response_type", "Response type parameter is invalid or unsupported");
		}
		// TODO: check for per-client response_type restrictions
		// Public clients doesn't need "code"
		// Confidetial clients may be restricted to use "token" (implicit grant type)
		// @see http://tools.ietf.org/html/rfc6749#section-3.1.2.2

		// verify scope with some regular expression
		if ($scope and !preg_match($this->scopeRegEx, $scope)) {
			throw new OAuth2Exception("invalid_scope", "The requested scope is invalid or malformed");
		}
		// check the scope is supported
		if ($scope and !$this->checkScope($scope)) {
			throw new OAuth2Exception("invalid_scope", "The requested scope is invalid or unknown");
		}
		// check if requested scope MUST be set
		if (!$scope and empty($this->config["default_scope"])) {
			throw new OAuth2Exception("invalid_scope", "The scope is mandatory");
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
}
