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
require "OAuth2Example.php";

$oauth = new OAuth2Example;
$error = "";

if ($_POST) {
	if (!empty($_POST["submit_user"])) {
		try {
			$oauth->saveUser($_POST["username"], $_POST["password"]);
			echo "User created";
			exit;

		} catch (OAuth2Exception $e) {
			$error = $e->error_description;
		}

	}
	elseif (!empty($_POST["submit_client"])) {
		try {
			$oauth->saveClient($_POST["client_id"], $_POST["client_type"], $_POST["redirect_uri"], $_POST["client_secret"]);
			echo "Client created";
			exit;
		} catch (OAuth2Exception $e) {
			$error = $e->error_description;
		}
	}
}
?>
<html>
<head>
	<title>Registration</title>
	<style>
.error {
	color: red;
}
	</style>
</head>
<body>
<?php if ($error) : ?>
	<p class="error"><?= $error; ?></p>
<?php endif; ?>
	<form method="post" action="">
		<p><strong>User Registration</strong></p>
		<p>
			<label>Username:
				<input type="text" name="username" value="<?= empty($_POST["username"]) ? "" : $_POST["username"];?>" /> *
			</label>
		</p>
		<p>
			<label>Password:
				<input type="password" name="password" value="" /> *
			</label>
		</p>
		<input type="submit" name="submit_user" value="Save" />
	</form>

	<br /><br /><br />
	<form method="post" action="">
		<p><strong>Client Registration</strong></p>
		<p>
			<label>Client ID:
				<input type="text" name="client_id" value="<?= empty($_POST["client_id"]) ? "" : $_POST["client_id"];?>" /> *
			</label>
		</p>
		<p>
			<label>Client Type:
				<select name="client_type">
					<option value=""></option>
					<option value="public"<?= (!empty($_POST["client_type"]) and $_POST["client_type"] == "public") ? ' selected="selected"' : ""; ?>>Public</option>
					<option value="confidential"<?= (!empty($_POST["client_type"]) and $_POST["client_type"] == "confidential") ? ' selected="selected"' : ""; ?>>Confidential</option>
				</select> *
			</label>
		</p>
		<p>
			<label>Redirect URI:
				<input type="text" name="redirect_uri" value="<?= empty($_POST["redirect_uri"]) ? "" : $_POST["redirect_uri"];?>" /> *
			</label>
		</p>
		<p>
			<label>Secret:
				<input type="password" name="client_secret" value="" />
			</label>
		</p>
		<input type="submit" name="submit_client" value="Save" />
	</form>
</body>
</html>
