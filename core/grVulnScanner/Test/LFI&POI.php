<?php
/**
 * Created by PhpStorm.
 * User: zik
 * Date: 4/15/16
 * Time: 10:47 PM
 */

//------------TEST1 - PASSED----------------//
//include(escapeshellcmd(htmlentities($_POST['id']))); #VUL
//require_once addslashes(htmlentities($_POST['id'])); #VUL
//include(pathinfo(htmlentities($_POST['id']))); #NOT VUL
//$user_data = unserialize($_GET['data']); #VUL
//
//function purify1($string, $con, $dummy){
//    return addslashes($string);
//}
//function purify2($string, $con, $dummy){
//    return basename($string);
//}
//include purify1(($_GET['abc']), 15, 123); #VUL
//require purify2(($_GET['cde']), 15, 123); #NOT VUL
//unserialize(substr(($_GET['cde']),15)); #NOT VUL
//unserialize(substr(($_GET['cde']))); #VUL
//------------ENDTEST1----------------//


//------------TEST2 - PASSED----------------//
//$a = $_POST['id'];
//include(escapeshellcmd(htmlentities("Scalar_Encapsed $a"))); #VUL
//require_once addslashes(htmlentities("Scalar_Encapsed $a")); #VUL
//include(pathinfo(htmlentities("Scalar_Encapsed $a"))); #NOT VUL
//$user_data = unserialize("Scalar_Encapsed $a"); #VUL
//unserialize(substr(("Scalar_Encapsed $a"),15)); #NOT VUL
//unserialize(substr(("Scalar_Encapsed $a"))); #VUL
//------------ENDTEST2----------------//

//------------TEST3 - PASSED----------------//
//include(escapeshellcmd(htmlentities("concat string".$_COOKIE['a']))); #VUL
//require_once pathinfo(htmlentities("concat string".$_COOKIE['a'])); #NOT VUL
//$user_data = unserialize("concat string".$_COOKIE['a']); #VUL
//unserialize(substr(("concat string".$_COOKIE['a']),15)); #NOT VUL
//unserialize(nonDefinedFunc(("concat string".$_COOKIE['a']))); #VUL
//------------ENDTEST3----------------//

//------------TEST4 - PASSED----------------//
//$a = 'concat operator';
//$a .= $_GET['filename'];
//include(escapeshellcmd(htmlentities($a))); #VUL
//require_once pathinfo(htmlentities($a)); #NOT VUL
//$user_data = unserialize($a); #VUL
//unserialize(substr(($a),15)); #NOT VUL
//unserialize(nonDefinedFunc(($a))); #VUL
//------------ENDTEST4----------------//

//------------TEST5 - PASSED----------------//
//$host = 'google';
//if (isset( $_GET['host'] ) )
//    $host = $_GET['host'];
//include("nslookup " . $host);
//if ($_COOKIE=='admin') unserialize("nslookup " . $host);
//------------ENDTEST5----------------//

function purify1($string){
    return htmlentities($string);
}
function purify2($string){
    return escapeshellarg($string);
}
function simulate($param1, $param2){
    return $param1;
}
//echo parse_str($_GET['a'], 15, $_GET['a']);
//echo abc($_GET['test']);
echo lolo(15, $_GET['a']);
include "commandInjection".'.php';
#with built-in functions and undefined functions: the final param is the determination
print urlencode(unserialize($_GET['a']));
print $_GET['a'];