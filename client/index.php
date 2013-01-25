<?php
	$redirect_uri = urlencode("http://client.auth.loc/redirect.php");
?>
<a href="http://auth.loc/auth.php?response_type=code&amp;client_id=test&amp;redirect_uri=<?= $redirect_uri;?>">Login</a>

