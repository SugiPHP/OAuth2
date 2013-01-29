<?php
/**
 * OAuth2.0 Authorization Server example
 * This is NOT a production ready.
 * Use it as a reference only!
 * 
 * @package OAuth2
 */

error_reporting(-1);

require __DIR__ . "/lib/OAuth2.php";
require __DIR__ . "/lib/IOAuth2Tokens.php";
require __DIR__ . "/lib/IOAuth2Codes.php";
require __DIR__ . "/lib/IOAuth2Implicit.php";
require __DIR__ . "/lib/IOAuth2DynamicURI.php";
require __DIR__ . "/lib/IOAuth2RefreshTokens.php";

class OAuth2example extends OAuth2 implements IOAuth2Tokens, IOAuth2Codes, IOAuth2Implicit, IOauth2DynamicURI, IOAuth2RefreshTokens
{
	/**
	 * PDO handler
	 */
	public $db;

	public function __construct()
	{
		parent::__construct(array(
			"scopes" 			=> "basic extended",
			"default_scope"		=> "basic",
			"code_size"			=> 32,
			"code_expires_in"	=> 120, // much more than needed. Only for testing purposes
			"token_expires_in" 	=> 900, // 15 minutes
		));

		// Establish a database connection
		$this->db = new PDO('mysql:host=localhost;dbname=test', "test", "test");
		// throw exceptions on database errors
		$this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	}

	/**
	 * Implements IOAuth2Tokens::getClient()
	 */
	function getClient($client_id)
	{
		$stmnt = $this->db->prepare("SELECT * FROM oauth_clients WHERE client_id = :client_id");
		$stmnt->bindParam(":client_id", $client_id);
		$stmnt->execute();
		$client = $stmnt->fetch();
		
		return ($client) ? $client : null;
	}

	/**
	 * Implements IOAuth2Tokens::saveToken()
	 */
	function saveToken($token, $client_id, $user_id, $expires, $scope, $code = null)
	{
		$stmnt = $this->db->prepare("INSERT INTO oauth_tokens (token, client_id, user_id, expires, scope, code) "
			." VALUES (:token, :client_id, :user_id, :expires, :scope, :code)");
		$stmnt->bindParam(":token", $token);
		$stmnt->bindParam(":client_id", $client_id);
		$stmnt->bindParam(":user_id", $user_id);
		$stmnt->bindParam(":expires", $expires);
		$stmnt->bindParam(":scope", $scope);
		$stmnt->bindParam(":code", $code);
		$stmnt->execute();
	}

	/**
	 * Implements IOAuth2Tokens::revokeToken()
	 */
	function revokeToken($token)
	{
		$stmnt = $this->db->prepare("UPDATE oauth_tokens SET revoked = 1 WHERE token = :token");
		$stmnt->bindParam(":token", $token);
		$stmnt->execute();
	}

	/**
	 * Implements IOAuth2Codes::saveAuthCode()
	 */
	function saveAuthCode($code, $client_id, $user_id, $expires, $redirect_uri, $scope)
	{
		$stmnt = $this->db->prepare("INSERT INTO oauth_codes (code, client_id, user_id, expires, scope, redirect_uri) "
			." VALUES (:code, :client_id, :user_id, :expires, :scope, :redirect_uri)");
		$stmnt->bindParam(":code", $code);
		$stmnt->bindParam(":client_id", $client_id);
		$stmnt->bindParam(":user_id", $user_id);
		$stmnt->bindParam(":expires", $expires);
		$stmnt->bindParam(":scope", $scope);
		$stmnt->bindParam(":redirect_uri", $redirect_uri);
		$stmnt->execute();
	}

	/**
	 * Implements IOAuth2Codes::getAuthCode()
	 */
	function getAuthCode($code)
	{
		$stmnt = $this->db->prepare("SELECT * FROM oauth_codes WHERE code = :code");
		$stmnt->bindParam(":code", $code);
		$stmnt->execute();
		$oauth_code = $stmnt->fetch();

		return ($oauth_code) ? $oauth_code : null;
	}

	/**
	 * Implements IOAuth2Codes::checkClientCredentials()
	 */
	function checkClientCredentials($client_id, $client_secret)
	{
		$client = $this->getClient($client_id);
		return $this->checkSecret($client["client_secret"], $client_secret);
	}

	/**
	 * Implements IOAuth2Codes::getTokenWithCode()
	 */
	function getTokenWithCode($code)
	{
		$stmnt = $this->db->prepare("SELECT token FROM oauth_tokens WHERE code = :code");
		$stmnt->bindParam(":code", $code);
		$stmnt->execute();
		$oauth_tokens = $stmnt->fetch();

		return empty($oauth_tokens["token"]) ? null : $oauth_tokens["token"];
	}

	/**
	 * Implements IOAuthDynamicURI::checkClientURI()
	 */
	function checkClientURI($redirect_uri, $client)
	{
		$reg_uri = $client["redirect_uri"];
		if (!$redirect_uri) return $reg_uri;
		return (strcasecmp(substr($redirect_uri, 0, strlen($reg_uri)), $reg_uri) === 0) ? $redirect_uri : false;
	}

	/**
	 * Implements IOAuth2RefreshTokens::saveRefreshToken()
	 */
	function saveRefreshToken($token, $client_id, $user_id, $expires, $scope, $code = null)
	{
		$stmnt = $this->db->prepare("INSERT INTO oauth_refresh_tokens (token, client_id, user_id, expires, scope, code) "
			." VALUES (:token, :client_id, :user_id, :expires, :scope, :code)");
		$stmnt->bindParam(":token", $token);
		$stmnt->bindParam(":client_id", $client_id);
		$stmnt->bindParam(":user_id", $user_id);
		$stmnt->bindParam(":expires", $expires);
		$stmnt->bindParam(":scope", $scope);
		$stmnt->bindParam(":code", $code);
		$stmnt->execute();
	}

	/**
	 * Implements IOAuth2RefreshTokens::getRefreshToken()
	 */
	function getRefreshToken($token)
	{
		// TODO:
	}

	/**
	 * Implements IOAuth2RefreshTokens::revokeRefreshTokensWithCode()
	 */
	function revokeRefreshTokensWithCode($code)
	{
		$stmnt = $this->db->prepare("UPDATE oauth_refresh_tokens SET revoked = 1 WHERE code = :code");
		$stmnt->bindParam(":code", $code);
		$stmnt->execute();
	}


	/*
	 * The following methods are not part of the specification
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
		// TODO:
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
		// TODO:
	}


	/**
	 * This method is not part of OAuth2 specification.
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
		// Check the client_id exists. Reusing existing code
		if ($this->getClient($client_id)) {
			throw new OAuth2Exception("client_id", "Client ID exists");
		}

		if (!preg_match($this->clientTypeRegEx, $client_type)) {
			throw new OAuth2Exception("client_type", "Client type is invalid");
		}

		if (!$redirect_uri) {
			throw new OAuth2Exception("redirect_uri", "Required redirect URI field is missing");	
		}
		// TODO: check redirect_uri
		
		if (!$client_secret and $client_type == "confidential") {
			throw new OAuth2Exception("client_secret", "Client secret must be provided for confidential clients");
		}

		// hash the secret
		$secret_hash = $this->cryptSecret($client_secret);
		
		$stmnt = $this->db->prepare("INSERT INTO oauth_clients (client_id, client_type, redirect_uri, client_secret) "
			." VALUES (:client_id, :client_type, :redirect_uri, :client_secret)");
		$stmnt->bindParam(":client_id", $client_id);
		$stmnt->bindParam(":client_type", $client_type);
		$stmnt->bindParam(":redirect_uri", $redirect_uri);
		$stmnt->bindParam(":client_secret", $secret_hash);
		$stmnt->execute();
	}
}
