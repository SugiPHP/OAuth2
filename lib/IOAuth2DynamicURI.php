<?php
/**
 * OAuth2.0 Authorization Server
 * 
 * @package OAuth2
 */

/**
 * Implement this interface if the client can register multiple redirection URI's, or to register only part of the URI, 
 * or not to register any redirection URI as specified in the standard
 */
interface IOAuth2DynamicURI extends IOAuth2Tokens
{
	/**
	 * Checks redirect_uri extracted from the request against the registered redirect URIs for the client
	 * 
	 * @param string $redirect_uri - redirect URI extracted from the OAuth2 request
	 * @param array $client - Client data fetch by IOAuth2Tokens::getClient()
	 * @return string - checked redirect URI. If the 
	 */
	function checkClientURI($redirect_uri, $client);
}
