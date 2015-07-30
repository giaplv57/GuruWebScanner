<?php
$a = $_POST["a"];
$b = "";
echo testFunc($a);
echo testFunc($b);
echo cleanFunc($a);
test($a);
function testFunc($arg) {
	echo $arg;
	return $arg;
}
function cleanFunc($arg) {
	return htmlentities($arg);
}
