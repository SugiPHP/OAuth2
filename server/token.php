<?php
/**
 * Token endpoint.
 * The client (OAuth2 client) uses this endpoint to exchange authorization grant for an access token or refresh token
 * @see http://tools.ietf.org/html/rfc6749#section-3.2
 *
 * @package OAuth2
 * @category example
 */

require "OAuth2Example.php";

// TODO: this is better to be moved in OAuth2 or ?
if (!isset($_SERVER["PHP_AUTH_USER"])) {
	header('WWW-Authenticate: Basic realm="OAuth2 Server"');
	header("HTTP/1.0 401 Unauthorized");
	echo json_encode(array("error" => "unauthorized_client", "error_description" => "The server accepts only HTTP Basic Authentication scheme"));
	exit;
}
if (!$_POST) {
	header("HTTP/1.0 405 Method Not Allowed");
	echo json_encode(array("error" => "invalid_request", "error_description" => "The page accepts only HTTP POST requests"));
	exit;
}

$auth = new OAuth2Example();
try {
	// check client request
	$requestParams = $auth->tokenRequest();
} catch (OAuth2Exception $e) {
	$auth->handleException($e);
}
