<?php
/**
 * OAuth2.0 Authorization Server
 * 
 * @package OAuth2
 */

/**
 * Implement this interface you want to support refresh tokens
 */
interface IOAuth2RefreshTokens
{
	function saveRefreshToken($token, $client_id, $user_id, $expires, $scope, $code = NULL);

	function getRefreshToken($token);

	function revokeRefreshTokensWithCode($code);
}
