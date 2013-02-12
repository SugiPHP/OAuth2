<?php
/**
 * Resource Server resource endpoint.
 * This is not a part of OAuth2 authorization server.
 * 
 * @package OAuth2
 * @category example
 */

error_reporting(-1);
require "../vendor/autoload.php";
require "ResourceServerExample.php";

$rserver = new ResourceServerExample();
try {
	$t = $rserver->verifyToken("basic");
	echo json_encode(array("user" => $t["user_id"], "eyes" => "green", "hair" => "brown"));
	exit;
}
catch (OAuth2\Exception $e) {
	$rserver->handleException($e);
}
