<?php
/**
 * OAuth2.0 Authorization Server
 * 
 * @package OAuth2
 */

require_once __DIR__ . "/IOAuth2Tokens.php";

/**
 * Implement this interface to use authorization codes.
 * @see http://tools.ietf.org/html/rfc6749#section-1.3.1
 */
interface IOauth2Codes extends IOAuth2Tokens
{
	/**
	 * Saves authorization request code. Based on this code the client will ask for access token.
	 * 
	 * @param string $code
	 * @param string $client_id
	 * @param mixed $user_id - the value passed in OAuth::grantAccess() method
	 * @param integer $expires
	 * @param string $redirect_uri
	 * @param string $scope
	 */
	function saveAuthCode($code, $client_id, $user_id, $expires, $redirect_uri, $scope);

	/**
	 * Reads authorization code data from the storage.
	 * @see IOAuth2Codes::saveAuthCode()
	 * 
	 * @param string $code
	 * @return array|NULL - An associative array:
	 *  - user_id
	 *  - client_id
	 *  - expires
	 *  - redirect_uri
	 *  - scope
	 */
	function getAuthCode($code);

	/**
	 * Checks sended client credentials are identical to those saved in the DB
	 * 
	 * @param string $client_id
	 * @param string $client_secret
	 * @return boolean
	 */
	function checkClientCredentials($client_id, $client_secret);

	/**
	 * Fetches a token issued in exchange of the code
	 * 
	 * @param string $code
	 * @return string|NULL - token issued or NULL if no token is issued based on the code
	 */
	function getTokenWithCode($code);
}
