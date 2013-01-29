<?php
/**
 * OAuth2.0 Authorization Server
 * 
 * @package OAuth2
 */

/**
 * This interface MUST be implemented to use OAuth2 server
 */
interface IOAuth2Tokens
{
	/**
	 * Reads client details from storage like DB
	 * Client SHOULD be previously be registered on the oauth2 server
	 * @see http://tools.ietf.org/html/rfc6749#section-3.1.2.2
	 * 
	 * @param string $client_id - unique client ID
	 * @return array|NULL - An associative array:
	 *  - redirect_uri string - registered redirect URI
	 *  - client_type - "public" or "confidential"
	 */
	function getClient($client_id);

	/**
	 * Saves access token issued by the server.
	 * 
	 * @param $user_id - the value passed in OAuth2::grantAccess() method
	 * @param string $client_id
	 * @param string $token
	 * @param integer $expires - timestamp when the token MUST be invalidated
	 * @param string $scope - the scope granted by the resource owner (user)
	 * @param string $code - OPTIONAL the authorization code used for issuing this token
	 */
	function saveToken($user_id, $client_id, $token, $expires, $scope, $code = null);

	/**
	 * Marks the token as invalid.
	 * You MUST NOT delete a token. Set some flag instead
	 * 
	 * @param string $token
	 */
	function revokeToken($token);
}
