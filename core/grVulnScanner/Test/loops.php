<?php
$a = array("",htmlentities($_POST["a"]));
for ($i = 0; $i < count($a); $i++) {
	$b[$i] = base64_decode($a[$i]);
}
echo $b[1];
