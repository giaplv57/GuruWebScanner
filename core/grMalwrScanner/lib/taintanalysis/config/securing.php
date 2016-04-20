<?php
	$F_SECURING_BOOL = array(
		'is_bool',
		'is_double',
		'is_float',
		'is_real',
		'is_long',
		'is_int',
		'is_integer',
		'is_null',
		'is_numeric',
		'is_finite',
		'is_infinite',
		'ctype_alnum',
		'ctype_alpha',
		'ctype_cntrl',
		'ctype_digit',
		'ctype_xdigit',
		'ctype_upper',
		'ctype_lower',
		'ctype_space',
		'in_array',
		'preg_match',
		'preg_match_all',
		'fnmatch',
		'ereg',
		'eregi'
	);
	
	$F_SECURING_STRING = array(
		'intval',
		'floatval',
		'doubleval',
		'filter_input',
		'urlencode',
		'rawurlencode',
		'round',
		'floor',
		'strlen',
		'strrpos',
		'strpos',
		'strftime',
		'strtotime',
		'md5',
		'md5_file',
		'sha1',
		'sha1_file',
		'crypt',
		'crc32',
		'hash',
		'mhash',
		'hash_hmac',
		'password_hash',
		'mcrypt_encrypt',
		'mcrypt_generic',
		'base64_encode',
		'ord',
		'sizeof',
		'count',
		'bin2hex',
		'levenshtein',
		'abs',
		'bindec',
		'decbin',
		'dechex',
		'decoct',
		'hexdec',
		'rand',
		'max',
		'min',
		'metaphone',
		'tempnam',
		'soundex',
		'money_format',
		'number_format',
		'date_format',
		'filetype',
		'nl_langinfo',
		'bzcompress',
		'convert_uuencode',
		'gzdeflate',
		'gzencode',
		'gzcompress',
		'http_build_query',
		'lzf_compress',
		'zlib_encode',
		'imap_binary',
		'iconv_mime_encode',
		'bson_encode',
		'sqlite_udf_encode_binary',
		'session_name',
		'readlink',
		'getservbyport',
		'getprotobynumber',
		'gethostname',
		'gethostbynamel',
		'gethostbyname',
	);
	
	$F_INSECURING_STRING = array(
		'base64_decode',
		'htmlspecialchars_decode',
		'html_entity_decode',
		'bzdecompress',
		'chr',
		'convert_uudecode',
		'gzdecode',
		'gzinflate',
		'gzuncompress',
		'lzf_decompress',
		'rawurldecode',
		'urldecode',
		'zlib_decode',
		'imap_base64',
		'imap_utf7_decode',
		'imap_mime_header_decode',
		'iconv_mime_decode',
		'iconv_mime_decode_headers',
		'hex2bin',
		'quoted_printable_decode',
		'imap_qprint',
		'mb_decode_mimeheader',
		'bson_decode',
		'sqlite_udf_decode_binary',
		'utf8_decode',
		'recode_string',
		'recode'
	);

	$F_SECURING_XSS = array(
		'htmlentities',
		'htmlspecialchars',
		'highlight_string',
	);	
	
	$F_SECURING_SQL = array(
		'addslashes',
		'dbx_escape_string',
		'db2_escape_string',
		'ingres_escape_string',
		'maxdb_escape_string',
		'maxdb_real_escape_string',
		'mysql_escape_string',
		'mysql_real_escape_string',
		'mysqli_escape_string',
		'mysqli_real_escape_string',
		'pg_escape_string',	
		'pg_escape_bytea',
		'sqlite_escape_string',
		'sqlite_udf_encode_binary',
		'cubrid_real_escape_string',
	);	
		
	$F_SECURING_PREG = array(
		'preg_quote'
	);	
	
	$F_SECURING_FILE = array(
		'basename',
		'dirname',
		'pathinfo'
	);
	
	$F_SECURING_SYSTEM = array(
		'escapeshellarg',
		'escapeshellcmd'
	);	
	
	$F_SECURING_XPATH = array(
		'addslashes'
	);
	
	$F_SECURING_LDAP = array(
	);
	
	$F_SECURES_ALL = array_merge(
		$F_SECURING_XSS, 
		$F_SECURING_SQL,
		$F_SECURING_PREG,
		$F_SECURING_FILE,
		$F_SECURING_SYSTEM,
		$F_SECURING_XPATH
	);	
	
	$F_QUOTE_ANALYSIS = $F_SECURING_SQL;
		
?>	