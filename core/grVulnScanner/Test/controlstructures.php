<?php
if (true) {
	$a = $_POST["a"];
} elseif (false) {
	$a = $_POST["b"];
} else {
	$a = "";
}
echo $a;
