<?php
	session_start();


	$redirect_uri = "http://client.auth.loc/redirect.php?rand=".mt_rand(100, 999);
	$state = md5(uniqid());

	$_SESSION["redirect_uri"] = $redirect_uri;
	$_SESSION["state"] = $state;
?>
<a href="http://auth.loc/auth.php?response_type=code&amp;client_id=client1&amp;state=<?= $state;?>&amp;redirect_uri=<?= urlencode($redirect_uri);?>">Login</a>
<br />
<a href="http://auth.loc/auth.php?response_type=token&amp;client_id=client1&amp;redirect_uri=<?= urlencode($redirect_uri);?>">Implicit</a>

