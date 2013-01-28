<?php
	session_start();

	$error = empty($_GET["error"]) ? "" : $_GET["error"];
	$error_description = empty($_GET["error_description"]) ? "" : $_GET["error_description"];
	
	$code = empty($_GET["code"]) ? "" : $_GET["code"];
	$state = empty($_GET["state"]) ? "" : $_GET["state"];
	$scope = empty($_GET["scope"]) ? "" : $_GET["scope"];

	if ($error) {
		echo "<h1>$error</h1>";
		if ($error_description) {
			echo "<p>$error_description</p>";
		}
		exit;
	}
?>
<!doctype html>
<html>
<head>
	<meta charset="utf-8" />
	<title>Client endpoint</title>
</head>
<body>
	<form name="" action="http://test:tset@auth.loc/token.php" method="post">
		<input type="hidden" name="grant_type" value="authorization_code" />
		<input type="hidden" name="code" value="<?= $code;?>" />
		<input type="submit" value="go" />
	</form>
</body>
</html>
