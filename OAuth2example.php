<?php

require "lib/OAuth2.php";

class OAuth2example extends OAuth2
{
	public function __construct()
	{
		parent::__construct(array(
			"scopes" 		=> "basic user_id example",
			"default_scope"	=> "basic",
		));
	}

	protected function getClient($client_id)
	{
		if ($client_id == "test") return array(
			"redirect_uri" 	=> "http://localhost",
			"client_type" 	=> "public" // "public" or "confidential"
		);

		if ($client_id == "test2") return array(
			"redirect_uri" 	=> "http://localhost/",
			"client_type" 	=> "confidential"
		);

		return null;
	}
}
