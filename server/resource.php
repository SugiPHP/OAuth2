<?php namespace OAuth2;
/**
 * Resource Server resource endpoint.
 * This is not a part of OAuth2 authorization server.
 * 
 * @package OAuth2
 * @category example
 */

require "OAuth2ResourceServerExample.php";

$rserver = new OAuth2ResourceServerExample;
try {
	$t = $rserver->verifyToken("basic");
	echo json_encode(array("user" => $t["user_id"], "eyes" => "green", "hair" => "brown"));
	exit;
}
catch (OAuth2Exception $e) {
	$rserver->handleException($e);
}
