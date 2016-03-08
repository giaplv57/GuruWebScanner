<?php
class TypoDB {
    public function exec_INSERTquery($table, $fields_values) {
        // Potential vulnerability if the $field_values array contains tainted keys
        mysql_query($table);
    }
    
    public function exec_INSERTmultipleRows($table, array $fields, array $rows, $no_quote_fields) {
        // Potential vulnerability if the $field_values array contains tainted keys
        mysql_query($table);
	mysql_query($fields);
    }
    
    public function exec_DELETEquery($table, $where) {
        mysql_query($table);
	mysql_query($where);
    }

    public function exec_SELECTquery($select_fields, $from_table, $where_clause, $groupBy, $orderBy, $limit) {
        mysql_query($select_fields);
	mysql_query($from_table);
	mysql_query($where_clause);
	mysql_query($groupBy);
	mysql_query($orderBy);
	mysql_query($limit);
    }

    public function exec_SELECT_mm_query($select, $local_table, $mm_table, $foreign_table, $whereClause, $groupBy, $orderBy, $limit) {
        mysql_query($select);
	mysql_query($local_table);
	mysql_query($mm_table);
	mysql_query($foreign_table);
	mysql_query($whereClause);
	mysql_query($groupBy);
	mysql_query($orderBy);
	mysql_query($limit);
    }

    public function exec_SELECT_queryArray($queryParts) {
        mysql_query($queryParts['SELECT']);
	mysql_query($queryParts['FROM']);
	mysql_query($queryParts['WHERE']);
	mysql_query($queryParts['GROUPBY']);
	mysql_query($queryParts['ORDERBY']);
	mysql_query($queryParts['LIMIT']);
    }

    public function exec_SELECTgetSingleRow($select_fields, $from_table, $where_clause, $groupBy, $orderBy, $numIndex) {
        mysql_query($select_fields);
	mysql_query($from_table);
	mysql_query($were_clause);
	mysql_query($groupBy);
	mysql_query($orderBy);
	mysql_query($numIndex);
    }

    public function exec_SELECTgetRows($select_fields, $from_table, $where_clause, $groupBy, $orderBy, $limit, $uidIndexField) {
        mysql_query($select_fields);
	mysql_query($from_table);
	mysql_query($where_clause);
	mysql_query($groupBy);
	mysql_query($orderBy);
	mysql_query($limit);
    }

    public function exec_SELECTcountRows($field, $table, $where = '') {
        mysql_query($field);
	mysql_query($table);
	mysql_query($where);
    }

    public function exec_TRUNCATEquery($table) {
        mysql_query($table);
    }

    public function INSERTquery($table, $fields_values) {
        return $table;
    }
    
    public function INSERTmultipleRows($table, array $fields, array $rows, $no_quote_fields) {
        return $table ." ". $fields;
    }

    public function UPDATEquery($table, $where, $fields_values) {
        return $table ." ". $where;
    }

    public function DELETEquery($table, $where) {
        return $table ." ". $where;
    }
    
    public function SELECTquery($select_fields, $from_table, $where_clause, $groupBy, $orderBy, $limit) {
        return $select_fields ." ". $from_table ." ". $where_caluse ." ". $groupBy ." ". $orderBy ." ". $limit;
    }
    
    public function listQuery($field, $value, $table) {
        return $field;
    }
    
    public function searchQuery($searchWords, $fields, $table) {
        return $fields ." ". $table;
    }
    
    public function quoteStr($str, $table) {
        return mysql_real_escape_string($str);
    }
    
    public function fullQuoteStr($str, $table) {
        return '\''. mysql_real_escape_string($str) .'\'';
    }
    public function fullQuoteArray($arr, $table) {
        return mysql_real_escape_string($arr);
    }
    public function escapeStrForLike($str) {
        return "";
    }

    public function cleanIntArray($arr) {
        return "";
    }

    public function cleanIntList($list) {
        return "";
    }

    public function stripOrderBy($str) {
        return $str;
    }

    public function stripGroupBy($str) {
        return $str;
    }
    
    public function splitGroupOrderLimit($str) {
        return $str;
    }

    public function sql_query($query) {
        mysql_query($query);
    }

    public function admin_get_fields($tableName) {
        mysql_query($tableName);
    }

    public function admin_get_keys($tableName) {
        mysql_query($tableName);
    }

    public function admin_query($query) {
        mysql_query($query);
    }

}

class t3lib_div {

    public static _GP($str) {
        return $_GET[$str];
    }

    public static _GPmerged($str) {
        return $_GET[$str];
    }

    public static _GET($str) {
        return $_GET[$str];
    }

    public static _POST($str) {
        return $_POST[$str];
    }

    public static _GETset($str) {
        $_GET[$str] = "";
    }

}

$GLOBALS = array();
$GLOBALS['TYPO3_DB'] = new TypoDB();

