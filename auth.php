<?php
/**
 * Authorization endpoint.
 * The client (OAuth2 client) uses this endpoint to obtain authorization from the resource owner (user)
 *
 * @see http://tools.ietf.org/html/rfc6749#section-3.1
 *
 * @package OAuth2
 * @category example
 * @version 13.01.22
 */

require "lib/OAuth2.php";

// According to the RFC, this MUST be the first thing to do: 
// Auth server MUST verify the identity of the user.
// OAuth2 standard does not describe how the user (resource owner) authenticates to the server.
// Neither do we
$user_id = 1;
if (!$user_id) {
	// instead of throwing an exception we can navigate the user to the login page
	throw new \Exception("Unknown user");
}

$auth = new OAuth2(array(
	"scopes" 		=> "basic user_id example",
	"default_scope"	=> "basic",
));
try {
	// check client request
	$request = $auth->authRequest();
	var_dump($request);
} catch (OAuth2Exception $e) {
	echo $e;
}
