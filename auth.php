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

require "OAuth2example.php";

// According to the RFC, this MUST be the first thing to do: 
// Auth server MUST verify the identity of the user.
// OAuth2 standard does not describe how the user (resource owner) authenticates to the server.
// Neither do we
$user_id = 1;
if (!$user_id) {
	// instead of throwing an exception we can navigate the user to the login page
	throw new \Exception("Unknown user");
}


$auth = new OAuth2example();
try {
	// check client request
	$requestParams = $auth->authRequest();
} catch (OAuth2Exception $e) {
	echo $e;
}

if ($_POST) {
	if ($_POST["submit"] == "Grant access") {
		$auth->grantAccess($user_id);
	}
	else {
		$auth->denyAccess();
	}
}

// After we have checked the request we need to ask the user for authorization
?>
<html>
<head>
	<title><?= $requestParams["client_id"];?> needs your authorization</title>
</head>
<body>
	<form method="post" action="">
		<input type="submit" name="submit" value="Grant access" />
		<input type="submit" name="submit" value="Deny access" />
	</form>
</body>
</html>
