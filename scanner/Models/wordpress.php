<?php
class WPDB {
        public function prepare($arg) {
                return $arg;
        }
	public function get_results($arg) {
		mysql_query($arg);
	}
	public function get_row($arg) {
		mysql_query($arg);
	}
	public function get_col($arg) {
		mysql_query($arg);
	}
	public function get_var($arg) {
		mysql_query($arg);
	}
	public function escape($arg) {
		return mysql_real_escape_string($arg);
	}
}
$wpdb = new WPDB();
function esc_attr($a) {
	return htmlentities($a);
}

foreach ($_POST as $key => $val) {
	$_POST[$key] = mysql_real_escape_string($val);
}
foreach ($_GET as $key => $val) {
	$_GET[$key] = mysql_real_escape_string($val);
}
foreach ($_REQUEST as $key => $val) {
	$_REQUEST[$key] = mysql_real_escape_string($val);
}

