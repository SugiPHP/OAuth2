<?php
/**
 * OAuth2.0 Exception
 * 
 * @package OAuth2
 * @version 13.01.22
 */


class OAuth2Exception extends \Exception
{
	protected $error;
	protected $error_description;

	public function __construct($error, $error_description)
	{
		parent::__construct($error);

		$this->error = $error;
		$this->error_description = $error_description;
	}

	public function __toString()
	{
		return json_encode(array("error" => $this->error, "error_description" => $this->error_description));
	}
}
