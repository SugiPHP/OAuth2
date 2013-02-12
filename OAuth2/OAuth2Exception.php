<?php namespace OAuth2;
/**
 * @package OAuth2
 * @author Plamen Popov <tzappa@gmail.com>
 * @license MIT
 */

/**
 * OAuth2.0 Exception
 */
class OAuth2Exception extends \Exception
{
	public $error_description;

	public function __construct($error, $error_description)
	{
		parent::__construct($error);

		$this->error = $error;
		$this->error_description = $error_description;
	}

	public function __toString()
	{
		return json_encode(array("error" => $this->getMessage(), "error_description" => $this->error_description));
	}
}
