<?php namespace OAuth2;
/**
 * @package OAuth2
 * @author  Plamen Popov <tzappa@gmail.com>
 * @license MIT
 */

/**
 * Implement this interface if you want to support refresh tokens
 */
interface RefreshTokenInterface extends TokenInterface
{
	/**
	 * Save refresh token data for further use
	 * 
	 * @param string $token
	 * @param string $client_id
	 * @param mixed $user_id
	 * @param integer $expires - unix timestamp when refresh token is considered expired
	 * @param string $scope
	 * @param string $code OPTIONAL - the code in exchange of witch the refresh token was issued
	 */
	function saveRefreshToken($token, $client_id, $user_id, $expires, $scope, $code = NULL);

	/**
	 * Return refresh token data
	 * 
	 * @param string $token
	 * @return array|NULL - An associative array or NULL value if refresh token was not found
	 */
	function getRefreshToken($token);

	/**
	 * Search for all refresh tokens issued in exchange of the given code and revoke them
	 * 
	 * @param string $code
	 */
	function revokeRefreshTokensWithCode($code);
}
