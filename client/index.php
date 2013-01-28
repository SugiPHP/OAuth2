<?php
	session_start();

	$redirect_uri = urlencode("http://client.auth.loc/redirect.php?rand=".mt_rand(100, 999));
?>
<a href="http://auth.loc/auth.php?response_type=code&amp;client_id=test&amp;redirect_uri=<?= $redirect_uri;?>">Login</a>

