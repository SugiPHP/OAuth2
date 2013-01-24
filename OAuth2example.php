<?php

require "lib/OAuth2.php";
require "lib/IOAuth2Tokens.php";
require "lib/IOAuth2Codes.php";

class OAuth2example extends OAuth2 implements IOAuth2Tokens, IOAuth2Codes
{
	public function __construct()
	{
		parent::__construct(array(
			"scopes" 			=> "basic extended",
			"default_scope"		=> "basic",
			"code_size"			=> 32,
			"token_expires_in" 	=> 15*60,
			"code_expires_in"	=> 30,
		));
	}

	function getClient($client_id)
	{
		if ($client_id == "test") return array(
			"redirect_uri" 	=> "http://localhost",
			"client_type" 	=> "public" // "public" or "confidential"
		);

		if ($client_id == "test2") return array(
			"redirect_uri" 	=> "http://localhost/",
			"client_type" 	=> "confidential"
		);

		return null;
	}

	function saveToken($user_id, $client_id, $token, $expires)
	{
		// TODO: save it in the DB
	}

	function saveAuthCode($user_id, $client_id, $code, $expires, $redirect_uri)
	{
		// TODO: save it in the DB
	}

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
}
