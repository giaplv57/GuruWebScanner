<?php
/**
 * Created by PhpStorm.
 * User: zik
 * Date: 4/15/16
 * Time: 2:23 AM
 */
//'xpath_eval'					    , #=> array(array(2), $F_SECURING_XPATH),
//'xpath_eval_expression'			, #=> array(array(2), $F_SECURING_XPATH),
//'xptr_eval'						, #=> array(array(2), $F_SECURING_XPATH)

//------------TEST1 - PASSED----------------//
//function purify1($string, $con, $dummy){
//    return htmlentities($string);
//}
//
//function purify2($string){
//    return ($string);
//}
//
//$a = purify1(($_GET['abc']), 15, 123);
//eval($a);               #VUL
//assert($_GET['a']);     #VUL

//------------ENDTEST1----------------//

//------------TEST2 - PASSED----------------//
//print("Please specify the name of the file to delete");
//print("<p>");
//$file=$_GET['filename'];
//eval("rm $file");
//assert("rm $file");
//------------ENDTEST2----------------//

//------------TEST3 - PASSED----------------//
//eval('cat '.$_GET['filename']);
//assert('cat '.escapeshellcmd($_GET['filename']));
//------------ENDTEST3----------------//

//------------TEST4 - PASSED----------------//
//$a = 'cat';
//$a .= $_GET['filename'];
//eval($a);
//$b = 'cat';
//$b .= escapeshellcmd($_GET['filename']);
//assert($b);
//------------ENDTEST4----------------//

//------------TEST5 - PASSED----------------//
//$host = 'google';
//if (isset( $_GET['host'] ) )
//    $host = $_GET['host'];
//eval("nslookup " . $host);
//------------ENDTEST5----------------//

//------------TEST6 - PASSED----------------//
//$a = $_POST["a"];
//$b = "";
//eval(testFunc($a));
//assert(testFunc($b));
//system(cleanFunc($a));
//test($a);
//function testFunc($arg) {
//    echo $arg;
//    return $arg;
//}
//function cleanFunc($arg) {
//    return escapeshellarg($arg);
//}
//------------ENDTEST6----------------//

class TestClass {

    public $a;

    public function set($arg1) {
        $this->a = htmlentities($arg1);
    }

    public function get() {
        return $this->a;
    }

}

$a = new TestClass();
$a->set($_POST["a"]);
echo ($a->get());


