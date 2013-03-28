<?php
/**
 * @package    SugiPHP
 * @subpackage OAuth2
 * @author     Plamen Popov <tzappa@gmail.com>
 * @license    http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\OAuth2;

/**
 * Implement this interface if the client can register multiple redirection URI's, or to register only part of the URI, 
 * or not to register any redirection URI as specified in the standard
 */
interface DynamicUriInterface extends TokenInterface
{
	/**
	 * Checks redirect_uri extracted from the request against the registered redirect URIs for the client
	 * 
	 * @param string $redirect_uri - redirect URI extracted from the OAuth2 request
	 * @param array $client - Client data fetch by TokenInterface::getClient()
	 * @return string - checked redirect URI. If the 
	 */
	function checkClientURI($redirect_uri, $client);
}
