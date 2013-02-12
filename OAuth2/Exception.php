<?php namespace OAuth2;
/**
 * @package OAuth2
 * @author Plamen Popov <tzappa@gmail.com>
 * @license MIT
 */

/**
 * OAuth2 Exception
 */
class Exception extends \Exception
{
	public $error_description;

	public function __construct($error, $error_description = null)
	{
		parent::__construct($error);

		$this->error = $error;
		$this->error_description = $error_description;
	}

	public function __toString()
	{
		$e = array("error" => $this->getMessage());
		if (isset($this->error_description)) $e["error_description"] = $this->error_description;
		return json_encode($e);
	}
}
