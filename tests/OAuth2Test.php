<?php

require __DIR__.'/../OAuth2example.php';

class OAuth2Test extends PHPUnit_Framework_TestCase {

	/**
	 * @expectedException OAuth2Exception
	 * @expectedExceptionMessage invalid_request
	 */
	public function testAuthRequestWithNoResponseType()
	{
		$server = new OAuth2example;
		$server->authRequest();
	}

	/**
	 * @expectedException OAuth2Exception
	 * @expectedExceptionMessage invalid_request
	 */
	public function testAuthRequestWithUnrecognizedOrMalformedResponseType()
	{
		$server = new OAuth2example;
		$params = array("response_type" => "t0kEn", "client_id" => "test");
		$server->authRequest($params);
	}

	/**
	 * @expectedException OAuth2Exception
	 * @expectedExceptionMessage invalid_request
	 */
	public function testAuthRequestWithNoClientID()
	{
		$server = new OAuth2example;
		$params = array("response_type" => "code");
		$server->authRequest($params);
	}

	/**
	 * @expectedException OAuth2Exception
	 * @expectedExceptionMessage invalid_request
	 */
	public function testAuthRequestWithMalformatedClientID()
	{
		$server = new OAuth2example;
		$params = array("response_type" => "code", "client_id" => "te*st");
		$server->authRequest($params);
	}

	/**
	 * @expectedException OAuth2Exception
	 * @expectedExceptionMessage unauthorized_client
	 */
	public function testAuthRequestWithNonexistingClient()
	{
		$server = new OAuth2example;
		$params = array("response_type" => "code", "client_id" => "unexistingclient");
		$server->authRequest($params);
	}

	/**
	 * @expectedException OAuth2Exception
	 * @expectedExceptionMessage access_denied
	 */
	public function testAuthRequestWithWrongRedirectUri()
	{
		$server = new OAuth2example;
		$params = array("response_type" => "code", "client_id" => "test", "redirect_uri" => "http://wronguri.example.com/");
		$server->authRequest($params);
	}

	/**
	 * this is not working for now, since we are redirecting to some URI...
	 */
	// public function testAuthRequestWrongScope()
	// {
	// 	$server = new OAuth2example;
	// 	$params = array("response_type" => "code", "client_id" => "test", "redirect_uri" => "http://localhost", "scope" => "wrongscope");
	// 	$server->authRequest($params);
	// }

	/**
	 * @expectedException OAuth2Exception
	 * @expectedExceptionMessage invalid_request
	 */
	public function testTokenRequestWithNoGrantType()
	{
		$server = new OAuth2example;
		$params = array();
		$server->tokenRequest($params);
	}

	/**
	 * @expectedException OAuth2Exception
	 * @expectedExceptionMessage unsupported_grant_type
	 */
	public function testTokenRequestWithWrongGrantType()
	{
		$server = new OAuth2example;
		$params = array("grant_type" => "unsupported");
		$server->tokenRequest($params);
	}

	/**
	 * @expectedException OAuth2Exception
	 * @expectedExceptionMessage invalid_request
	 */
	public function testTokenRequestWithNoClientId()
	{
		$server = new OAuth2example;
		$params = array("grant_type" => "authorization_code");
		$server->tokenRequest($params);
	}
	
	/**
	 * @expectedException OAuth2Exception
	 * @expectedExceptionMessage invalid_request
	 */
	public function testTokenRequestWithMalformedClientId()
	{
		$server = new OAuth2example;
		$params = array("grant_type" => "authorization_code", "client_id" => "te*st");
		$server->tokenRequest($params);
	}
	
	/**
	 * @expectedException OAuth2Exception
	 * @expectedExceptionMessage unauthorized_client
	 */
	public function testTokenRequestWithUnexistingClientId()
	{
		$server = new OAuth2example;
		$params = array("grant_type" => "authorization_code", "client_id" => "unexistingclient");
		$server->tokenRequest($params);
	}

	/**
	 * @expectedException OAuth2Exception
	 * @expectedExceptionMessage invalid_request
	 */
	public function testTokenRequestWithMissingCode()
	{
		$server = new OAuth2example;
		$params = array("grant_type" => "authorization_code", "client_id" => "test");
		$server->tokenRequest($params);
	}

	// try {$server->tokenRequest($params);} catch (OAuth2Exception $e) {echo $e;}
	// $params = array("redirect_uri" => "http://wronguri.example.com/");

}
