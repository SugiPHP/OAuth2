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
$error = "";

if ($_POST) {
	try {
		$oauth->saveClient($_POST["client_id"], $_POST["client_type"], $_POST["redirect_uri"], $_POST["client_secret"]);
		echo "Client created";
		exit;
	} catch (OAuth2Exception $e) {
		$error = $e->error_description;
	}
}
?>
<html>
<head>
	<title>Client Registration</title>
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
		<input type="submit" name="submit" value="Save" />
	</form>
</body>
</html>
