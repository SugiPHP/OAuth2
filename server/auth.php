<?php
/**
 * Authorization endpoint.
 * The client (OAuth2 client) uses this endpoint to obtain authorization from the resource owner (user)
 *
 * @see http://tools.ietf.org/html/rfc6749#section-3.1
 *
 * @package OAuth2
 * @category example
 */

error_reporting(-1);
require "../vendor/autoload.php";
require "Example.php";

// According to the RFC, this MUST be the first thing to do: 
// Auth server MUST verify the identity of the user.
// OAuth2 standard does not describe how the user (resource owner) authenticates to the server.
// Neither do we
$user_id = 1;
if (!$user_id) {
	// instead of throwing an exception we can navigate the user to the login page
	throw new \Exception("Unknown user");
}


$auth = new Example();
try {
	$request = $auth->authRequest($_GET);
} catch (OAuth2\Exception $e) {
	$auth->handleException($e);
	exit;
}


// Check if the user already (probably some time ago) has granted access for the scope and for the client.
// If so, we can skip next step and automatically grant access
if ($auth->getAccessGranted($user_id, $request["client_id"], $request["scope"])) {
	$auth->grantAccess($user_id);
}

if ($_POST) {
	if ($_POST["submit"] == "Grant access") {
		// We can store (in the DB) the grant access for further use.
		$auth->saveAccessGrant($user_id, $request["client_id"], $request["scope"]);
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
	<title>Authorization Request</title>
</head>
<body>
	<form method="post" action="">
		<h2><?= $request["client_id"];?></h2>
		<p><?= $request["client_id"];?> application needs your:
			<ul>
			<?php foreach(explode(" ", $request["scope"]) as $scope): ?>
				<li><?= $scope; ?> data</li>
			<?php endforeach; ?>
			</ul>
		</p>
		<input type="submit" name="submit" value="Grant access" />
		<input type="submit" name="submit" value="Deny access" />
	</form>
</body>
</html>
