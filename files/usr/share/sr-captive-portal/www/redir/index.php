<?php
header("Location: http://auth.net.studentrobotics.org/?from=" .
			urlencode( (isset($_SERVER["HTTPS"]) ? "https://" : "http://") . $_SERVER["HTTP_HOST"] . $_SERVER["REQUEST_URI"]) );
?>
