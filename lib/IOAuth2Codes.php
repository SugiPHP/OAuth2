<?php
/**
 * OAuth2.0 Authorization Server
 * 
 * @package OAuth2
 */

/**
 * Implement this interface to use authorization codes
 */
interface IOauth2Codes
{
	/**
	 * Saves authorization request code. Based on this code the client will ask for access token.
	 * 
	 * @param $user_id - the value passed in OAuth::grantAccess() method
	 * @param string $client_id
	 * @param string $code
	 */
	function saveAuthCode($user_id, $client_id, $code);

	/**
	 * Reads authorization code data from the storage.
	 * @see OAuth2::saveAuthCode()
	 * 
	 * @param string $code
	 * @return array|NULL - An associative array:
	 *  - user_id
	 *  - client_id
	 *  ...
	 */
	function getAuthCode($code);
}
