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
	 * @param $user_id - the value passed in OAuth::grantAccess() method
	 * @param string $client_id
	 * @param string $code
	 */
	function saveAuthCode($user_id, $client_id, $code, $expires, $redirect_uri);

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
	 */
	function getAuthCode($code);

	
	function checkClientCredentials($client_id, $client_secret);
}
