<?php
if (true) {
	$a = $_POST["a"];
} else {
	$a = $_POST["c"];
}
if (false) {
	$a = htmlentities($a);
} else {
	$a = htmlentities($a.$a);
}
echo $a;
