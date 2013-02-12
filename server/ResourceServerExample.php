<?php
/**
 * OAuth2.0 Resource Server example
 * This is NOT a production ready.
 * Use it as a reference only!
 * 
 * @package OAuth2
 * @category example
 */

use OAuth2\ResourceServer;

class ResourceServerExample extends ResourceServer
{
	/**
	 * PDO handler
	 */
	public $db;

	public function __construct()
	{
		parent::__construct(array(
			"accept_post_requests"	=> TRUE,
			"accept_get_requests"	=> TRUE
		));

		// Establish a database connection
		$this->db = new PDO('mysql:host=localhost;dbname=test', "test", "test");
		// throw exceptions on database errors
		$this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	}

	/**
	 * Implementation of OAuth2ResourceServer::getToken()
	 */
	function getToken($token)
	{
		// Parent class will handle revoked, expired and invalid in other way tokens, so no need to add "AND revoked = 0" in statement
		$stmnt = $this->db->prepare("SELECT * FROM oauth_tokens WHERE token = :token");
		$stmnt->bindParam(":token", $token);
		$stmnt->execute();
		$data = $stmnt->fetch();

		return empty($data["token"]) ? null : $data;
	}
}
