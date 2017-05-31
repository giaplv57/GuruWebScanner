<?php
	function block_filter($input){
		$input1 = strtolower($input);
		$blacklist = ARRAY ("insert", "select", "update", "delete", "distinct", "having", "truncate", "replace", "union", "handler", "like", "substring", "mid", "procedure", "limit", "order by", "group by", "union", "table", "outfile", "dumpfile", "load_file");
		foreach ($blacklist as $word){
			if (strpos($input1,$word) !== false) {
				return true;
			}
		}
		return false;
	}

	function add_addition_db($input){
		$badlist = ARRAY("~", "!", "@", "#", "%", "^", "&", "*", "(", ")", "_", "+", "-", "=", "{", "}", ";", "?", "/");
		foreach ($badlist as $char){
			if (strpos($input, $char) !== false){ 
				$input = str_replace($char, $char.'$', $input);	
			}
		}
		if (strpos($input, "\\") !== false){ 
			$input = str_replace("\\", "\\\\$", $input);	
		}
		return $input;
	}

	function add_addition_noti($input){
		$badlist = ARRAY("\\", "~", "!", "@", "#", "%", "^", "&", "*", "(", ")", "_", "+", "-", "=", "{", "}", ";", "?", "/");
		foreach ($badlist as $char){
			if (strpos($input, $char) !== false){ 
				$input = str_replace($char, $char.'$', $input);	
			}
		}
		return $input;
	}
?>