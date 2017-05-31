<?php 
	$length = 10;
	$secret_passwd = substr(str_shuffle(md5(time())),0,$length);
?>