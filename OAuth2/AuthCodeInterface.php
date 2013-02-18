<?php namespace OAuth2;
/**
 * @package OAuth2
 * @author  Plamen Popov <tzappa@gmail.com>
 * @license MIT
 */

/**
 * Implement this interface to use authorization codes.
 * @see http://tools.ietf.org/html/rfc6749#section-1.3.1
 */
interface AuthCodeInterface extends TokenInterface
{
	/**
	 * Saves authorization request code. Based on this code the client will ask for access token.
	 * 
	 * @param string $code
	 * @param string $client_id
	 * @param mixed $user_id - the value passed in Server::grantAccess() method
	 * @param integer $expires
	 * @param string $redirect_uri
	 * @param string $scope
	 */
	function saveAuthCode($code, $client_id, $user_id, $expires, $redirect_uri, $scope);

	/**
	 * Reads authorization code data from the storage.
	 * @see saveAuthCode()
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
	 * Fetches a token issued in exchange of the code
	 * 
	 * @param string $code
	 * @return string|NULL - token issued or NULL if no token is issued based on the code
	 */
	function getTokenWithCode($code);
}
