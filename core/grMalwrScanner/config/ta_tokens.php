<?php

final class Tokens
{	
	
	public static $TOKEN_IGNORE = array(
		T_BAD_CHARACTER,
		T_DOC_COMMENT,
		T_COMMENT,	
		T_INLINE_HTML,
		T_WHITESPACE,
		T_OPEN_TAG		
	);
	
	public static $TOKEN_LOOPCONTROL = array(	
		T_WHILE,
		T_FOR,
		T_FOREACH
	);
		
	public static $TOKEN_FLOWCONTROL = array(
		T_IF, 
		T_SWITCH, 
		T_CASE, 
		T_ELSE, 
		T_ELSEIF
	);	
		
	public static $TOKEN_ASSIGNMENT = array(
		T_AND_EQUAL,
		T_CONCAT_EQUAL,
		T_DIV_EQUAL,
		T_MINUS_EQUAL,
		T_MOD_EQUAL,
		T_MUL_EQUAL,
		T_OR_EQUAL,
		T_PLUS_EQUAL,
		T_SL_EQUAL,
		T_SR_EQUAL,
		T_XOR_EQUAL
	);
	
	public static $TOKEN_ASSIGNMENT_SECURE = array(
		T_DIV_EQUAL,
		T_MINUS_EQUAL,
		T_MOD_EQUAL,
		T_MUL_EQUAL,
		T_OR_EQUAL,
		T_PLUS_EQUAL,
		T_SL_EQUAL,
		T_SR_EQUAL,
		T_XOR_EQUAL
	);
	
	public static $TOKEN_OPERATOR = array(
		T_IS_EQUAL,
		T_IS_GREATER_OR_EQUAL,
		T_IS_IDENTICAL,
		T_IS_NOT_EQUAL,
		T_IS_NOT_IDENTICAL,
		T_IS_SMALLER_OR_EQUAL
	);
	
	public static $TOKEN_FUNCTIONS = array(
		T_STRING,
		T_EVAL,
		T_INCLUDE,
		T_INCLUDE_ONCE,
		T_REQUIRE,
		T_REQUIRE_ONCE
	);
	
	public static $TOKEN_INCLUDES = array(
		T_INCLUDE,
		T_INCLUDE_ONCE,
		T_REQUIRE,
		T_REQUIRE_ONCE
	);
	
	public static $TOKEN_XSS = array(
		T_PRINT,
		T_ECHO,
		T_OPEN_TAG_WITH_ECHO,
		T_EXIT
	);
	
	public static $TOKEN_CASTS = array(
		T_BOOL_CAST,
		T_DOUBLE_CAST,
		T_INT_CAST,
		T_UNSET_CAST,
		T_UNSET
	);
	
	public static $TOKEN_SPACEWRAP = array(
		T_AS,
		T_BOOLEAN_AND,
		T_BOOLEAN_OR,
		T_LOGICAL_AND,
		T_LOGICAL_OR,
		T_LOGICAL_XOR,
		T_SL,
		T_SR,
		T_CASE,
		T_ELSE,
		T_GLOBAL,
		T_NEW
	);
	
	public static $TOKEN_ARITHMETIC = array(
		T_INC,
		T_DEC
	);
	
	public static $TOKEN_OPERATOR = array(
		'+',
		'-',
		'*',
		'/',
		'%'
	);
	
	public static $TOKEN_SPACEWRAP = array(
		'.',
		'=',
		'>',
		'<',
		':',
		'?'
	);
}	
	
define('T_INCLUDE_END', 380);

?>	