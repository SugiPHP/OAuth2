<?php
/**
 * OAuth2.0 Authorization Server
 * 
 * @package OAuth2
 */

/**
 * Implement this interface if you want to support Resource Owner Password Credentials grant type
 */
interface IOAuth2Passwords
{	
	/**
	 * Retrieves info for a registered user, matching both username and password
	 * 
	 * @param string $username
	 * @param string $password
	 * @return integer|NULL - ID of the user if found, NULL otherwise
	 */
	function checkUserCredentials($username, $password);
}
