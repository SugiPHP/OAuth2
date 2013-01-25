<?php
/**
 * OAuth2.0 Authorization Server example
 * This is (and will not be) production ready example.
 * Use it as a reference only!
 * 
 * @package OAuth2
 */

require __DIR__ . "/lib/OAuth2.php";
require __DIR__ . "/lib/IOAuth2Tokens.php";
require __DIR__ . "/lib/IOAuth2Codes.php";
require __DIR__ . "/lib/IOAuth2Implicit.php";

class OAuth2example extends OAuth2 implements IOAuth2Tokens, IOAuth2Codes, IOAuth2Implicit
{
	
	public function __construct()
	{
		parent::__construct(array(
			"scopes" 			=> "basic extended",
			"default_scope"		=> "basic",
			"code_size"			=> 32,
			"code_expires_in"	=> 180, // much more than needed. Only for testing purposes
			"token_expires_in" 	=> 900, // 15 minutes
		));
	}

	/**
	 * Implements IOAuth2Tokens::getClient()
	 */
	function getClient($client_id)
	{
		if ($client_id == "test") return array(
			"redirect_uri" 	=> "http://client.auth.loc/redirect.php",
			"client_type" 	=> "confidential" // "public" or "confidential"
		);

		if ($client_id == "pubtest") return array(
			"redirect_uri" 	=> "http://client.auth.loc/redirect.php",
			"client_type" 	=> "public"
		);

		return null;
	}

	/**
	 * Implements IOAuth2Tokens::saveToken()
	 */
	function saveToken($user_id, $client_id, $token, $expires)
	{
		// TODO: save it in the DB
	}

	/**
	 * Implements IOAuth2Codes::saveAuthCode()
	 */
	function saveAuthCode($user_id, $client_id, $code, $expires, $redirect_uri)
	{
		// TODO: save it in the DB
	}

	/**
	 * Implements IOAuth2Codes::getAuthCode()
	 */
	function getAuthCode($code)
	{
		return array(
			"client_id" 	=> "test",
			"user_id"		=> 1,
			"expires" 		=> time() + 15,
			"redirect_uri" 	=> ""
		);
	}

	/**
	 * Implements IOAuth2Codes::checkClientCredentials()
	 */
	function checkClientCredentials($client_id, $client_password)
	{
		return true;
	}


	/*
	 * Some customizations bellow
	 */

	/**
	 * Checks the user already had granted access for this client with given scope.
	 * This method is not part of OAuth2 specification.
	 * @see OAuth2example::saveAccessGrant()
	 * 
	 * @param mixed $user_id
	 * @param string $client_id
	 * @param string $scope
	 * @return boolean
	 */
	public function getAccessGranted($user_id, $client_id, $scope)
	{
		return ($user_id == 1 and $client_id == "test" and $scope == "basic");
	}

	/**
	 * Store information that the user has granted access for the given scope to the client
	 * This method is not part of OAuth2 specification.
	 * @see OAuth2example::getAccessGranted()
	 * 
	 * @param mixed $user_id
	 * @param string $client_id
	 * @param string $scope
	 */
	public function saveAccessGrant($user_id, $client_id, $scope)
	{
		// TODO: save access grant
	}


	/**
	 * This is not part of the OAuth2.
	 * Only for reference what info is needed for client registrations.
	 * 
	 * @param string $client_id - REQUIRED
	 * @param string $client_type - REQUIRED one of "confidential" or "public"
	 * @param string $redirect_uri - REQUIRED
	 * @param string $client_secret - not required by the standard if the client type is public.
	 * Client secret can be omitted if some other form of authentication for confidential clients are
	 * implemented (e.g. public/private key pair) @see http://tools.ietf.org/html/rfc6749#section-2.3
	 */
	public function saveClient($client_id, $client_type, $redirect_uri, $client_secret)
	{
		if (!preg_match($this->clientIdRegEx, $client_id)) {
			throw new OAuth2Exception("client_id", "Client ID is invalid");
		}
		// TODO: check client_id exists

		if (!preg_match($this->clientTypeRegEx, $client_type)) {
			throw new OAuth2Exception("client_type", "Client type is invalid");
		}

		// TODO: check redirect_uri
		
		if (!$client_secret and $client_type == "confidential") {
			throw new OAuth2Exception("client_secret", "Client secret must be provided for confidential clients");
		}
	}
}
