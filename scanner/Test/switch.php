<?php
switch($a) {
	case "a":
		echo $_POST["a"];
		break;
	case "b":
		echo $_POST["b"];
	case "c":
		echo $_POST["c"];
		break;
	default:
		echo $_POST["d"];
}
