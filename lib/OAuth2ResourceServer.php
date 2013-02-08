<?php
/**
 * OAuth2.0 Resource Server
 * 
 * @package OAuth2
 */

require_once __DIR__ . "/OAuth2Exception.php";

abstract class OAuth2ResourceServer
{
	/**
	 * Regular expression to extract token from the HTTP headers
	 * @var string
	 */
	protected $bearerTokenRegEx = '#Bearer\s(\S+)#';

	/**
	 * HTTP status codes returned on errors
	 * @var array
	 */
	protected $HTTP_CODES = array(
		"invalid_request" 		=> "400 Bad Request",
		"invalid_token"			=> "401 Unauthorized",
		"insufficient_scope" 	=> "403 Forbidden",
	);

	/**
	 * handles the scope needed to access the requested resource
	 * @var string
	 */
	protected $scope;

	/**
	 * Storage for configuration settings
	 * @var array
	 */
	protected $config = array();


	public function __construct(array $config = array())
	{
		// Default configuration options
		$this->config = array(
			"accept_post_requests"	=> TRUE,
			"accept_get_requests"	=> FALSE
		);

		// Override default options
		foreach ($config as $name => $value) {
			$this->config[$name] = $value;
		}
	}

	/**
	 * Resource Request
	 * 
	 * @param string $scope - required scope to access requested resource. Space delimited if more than one scope is needed
	 * @return array - associative array holding token parameters such as:
	 *  - token (string)
	 *  - client_id (string)
	 *  - user_id (mixed|NULL)
	 */
	public function verifyToken($scope = null)
	{
		$this->scope = $scope;

		// Extract Bearer token
		if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
			$authorization = $_SERVER["HTTP_AUTHORIZATION"];
			if (!preg_match($this->bearerTokenRegEx, $authorization, $matches)) {
				throw new OAuth2Exception("", "");
			}
			$access_token = $matches[1];
		} elseif ($headers = apache_request_headers() and isset($headers["Authorization"])) {
			$authorization = $headers["Authorization"];
			if (!preg_match($this->bearerTokenRegEx, $authorization, $matches)) {
				throw new OAuth2Exception("", "");
			}
			$access_token = $matches[1];
		} elseif (isset($_POST["access_token"])) {
			if (!$this->config["accept_post_requests"]) {
				throw new OAuth2Exception("invalid_request", "Server does not support HTTP POST auth requests");
			}
			$access_token = $_POST["access_token"];
		} elseif (isset($_GET["access_token"])) {
			if (!$this->config["accept_get_requests"]) {
				throw new OAuth2Exception("invalid_request", "Server does not support HTTP GET auth requests");
			}
			$access_token = $_GET["access_token"];
		} else {
			throw new OAuth2Exception("", "");
		}

		if (!$access_token) {
			throw new OAuth2Exception("invalid_request", "Required token parameter is missing");
		}

		$tokenData = $this->getToken($access_token);

		if (!$tokenData) {
			throw new OAuth2Exception("invalid_token", "The token provided is invalid");
		}

		if (!empty($tokenData["revoked"])) {
			throw new OAuth2Exception("invalid_token", "The token provided is revoked");
		}

		if (empty($tokenData["expires"])) {
			throw new OAuth2Exception("server_error", "Token expire date is unavailable");
		}
		if ($tokenData["expires"] < time()) {
			throw new OAuth2Exception("invalid_token", "The token provided has expired");
		}

		if (!$this->checkScope($scope, $tokenData["scope"])) {
			throw new OAuth2Exception("insufficient_scope", "Requested resource requires privilege that is not granted by the owner");
		}

		return array(
			"token"			=> $access_token,
			"user_id" 		=> $tokenData["user_id"],
			"client_id" 	=> $tokenData["client_id"],
		);
	}

	/**
	 * Fetches stored information matching the given token.
	 * 
	 * @param string $token
	 * @return array|NULL - associative array as follows:
	 *  - expires - integer
	 *  - client_id - string
	 *  - user_id - mixed|NULL - NULL means that the token was issued by the OAuth server with client credentials (no user is involved)
	 *  - scope - string - space delimited values
	 *  - revoked - 0 indicating that the token is OK, and any other value indicating that the token is revoked for some reason
	 */
	abstract function getToken($token);

	/**
	 * Checks that the requested scope is within those granted by the user
	 * 
	 * @param string $scope
	 * @param string $granted_scope
	 * @return boolean
	 */
	protected function checkScope($scope, $granted_scope)
	{
		// if the required scope is not given, we will assume that any given scope is enough to process the request
		if (!$scope) return true;

		// if the resource requires some scope but the granted scope is not defined
		if (!$granted_scope) return false;

		return (count(array_diff(explode(" ", $scope), explode(" ", $granted_scope))) === 0);
	}

	/**
	 * Handles an exception thrown by this class
	 * @see http://tools.ietf.org/html/rfc6750#section-3.1
	 * 
	 * @param OAuth2Exception $e
	 */
	public function handleException(OAuth2Exception $e)
	{
		$error = $e->getMessage();
		$realm = ($this->scope) ? ' realm="' . $this->scope . '", ' : '';

		if (!$error) {
			header("HTTP/1.1 401 Unauthorized");
			header('WWW-Authenticate: Bearer');
		}
		else {
			header("HTTP/1.1 " . $this->HTTP_CODES[$error]);
			header('WWW-Authenticate: Bearer' . $realm . 'error="' . $error . '", error_description="' . $e->error_description . '"');
		}
	}
}
