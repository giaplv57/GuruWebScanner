<?php
	// filter input
	function filter($src) {
		$src = stripslashes($src);
        $src = strip_tags($src);
        $src = mysql_real_escape_string($src);
        $src = htmlentities($src);
        $src = htmlspecialchars($src);
        return $src;
	}
?>