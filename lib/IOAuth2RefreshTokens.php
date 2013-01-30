<?php
/**
 * OAuth2.0 Authorization Server
 * 
 * @package OAuth2
 */

require_once __DIR__ . "/IOAuth2Tokens.php";

/**
 * Implement this interface if you want to support refresh tokens
 */
interface IOAuth2RefreshTokens extends IOAuth2Tokens
{
	function saveRefreshToken($token, $client_id, $user_id, $expires, $scope, $code = NULL);

	function getRefreshToken($token);

	function revokeRefreshTokensWithCode($code);
}
