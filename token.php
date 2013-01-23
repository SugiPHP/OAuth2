<?php
/**
 * Token endpoint.
 * The client (OAuth2 client) uses this endpoint to exchange authorization grant for an access token or refresh token
 * @see http://tools.ietf.org/html/rfc6749#section-3.2
 *
 * @package OAuth2
 * @category example
 */

// to make a life a little bit easier temporary I will ignore specification and allow using GET request, instead of POST
require "OAuth2example.php";


$auth = new OAuth2example();
try {
	// check client request
	$requestParams = $auth->tokenRequest($_GET);
} catch (OAuth2Exception $e) {
	echo $e;
	exit;
}
