<?php
/**
 * Client Registration form.
 * This is not required by the OAuth2 specification
 * 
 * @see http://tools.ietf.org/html/rfc6749#section-2
 *
 * @package OAuth2
 * @category example
 */
require "OAuth2example.php";

$oauth = new OAuth2example;

if ($_POST) {
	$oauth->saveClient($_POST["client_id"], $_POST["client_type"], $_POST["redirect_uri"], $_POST["client_secret"]);
}
?>
<html>
<head>
	<title>Client Registration</title>
</head>
<body>
	<form method="post" action="">
		<p>
			<label>Client ID:
				<input type="text" name="client_id" value="" />
			</label>
		</p>
		<p>
			<label>Client Type:
				<select name="client_type">
					<option value="public">Public</option>
					<option value="confidential">Confidential</option>
				</select>
			</label>
		</p>
		<p>
			<label>Redirect URI:
				<input type="text" name="redirect_uri" value="" />
			</label>
		</p>
		<p>
			<label>Secret:
				<input type="password" name="client_secret" value="" />
			</label>
		</p>
		<input type="submit" name="submit" value="Save" />
	</form>
</body>
</html>
