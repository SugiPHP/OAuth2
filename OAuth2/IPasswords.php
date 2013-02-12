<?php namespace OAuth2;
/**
 * @package OAuth2
 * @author Plamen Popov <tzappa@gmail.com>
 * @license MIT
 */

/**
 * Implement this interface if you want to support Resource Owner Password Credentials grant type
 */
interface IPasswords extends ITokens
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
