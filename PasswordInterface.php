<?php
/**
 * @package    SugiPHP
 * @subpackage OAuth2
 * @author     Plamen Popov <tzappa@gmail.com>
 * @license    http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\OAuth2;

/**
 * Implement this interface if you want to support Resource Owner Password Credentials grant type
 */
interface PasswordInterface extends TokenInterface
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
