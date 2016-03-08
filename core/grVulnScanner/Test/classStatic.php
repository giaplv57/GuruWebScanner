<?php
class ost {
	public static function get() {
		return $_GET["flaf"];
	}
}
echo ost::get();
