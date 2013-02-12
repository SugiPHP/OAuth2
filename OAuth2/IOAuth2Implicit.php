<?php namespace OAuth2;
/**
 * @package OAuth2
 * @author Plamen Popov <tzappa@gmail.com>
 * @license MIT
 */

require_once __DIR__ . "/IOAuth2Tokens.php";

/**
 * Implement this interface to use implicit grant type
 * @see http://tools.ietf.org/html/rfc6749#section-1.3.2
 */
interface IOauth2Implicit extends IOAuth2Tokens
{

}
