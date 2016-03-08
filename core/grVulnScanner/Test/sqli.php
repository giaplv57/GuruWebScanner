<?php
ini_set('display_errors',1); 
error_reporting(E_ALL);
$db_username="root";
$db_password="root";
$database="guruWS";

#MYSQLI BELOW IS VULNERABLE BUT THAPS CAN'T DETECT!!
$con=mysqli_connect('localhost', $db_username, $db_password, $database);
// $a = mysqli_escape_string($con, $_GET["a"]);
$a = $_GET["a"]; // NGAY CA KHI KHONG DUNG mysqli_escape_string THI THAPS CUNG KHONG THE DETECT
$result = mysqli_query($con, "SELECT * from reports where shareID=$a");
var_dump(mysqli_fetch_array($result)); #POC: http://localhost/GuruWebScanner/scanner/Test/sqli.php?a=2 union all select 1,2,3,(select user()),5--

/*
#MYSQL BELOW IS THE SAME WITH ABOVE AND THAP CAN DETECT!!
mysql_connect('localhost', $db_username, $db_password);
mysql_select_db($database);
$a = mysql_real_escape_string($_GET["a"]);
$result = mysql_query("SELECT * from reports where shareID=$a");
var_dump(mysql_fetch_array($result)); #POC: http://localhost/GuruWebScanner/scanner/Test/sqli.php?a=1 union all select 1,2,(select user()),4,5-- -
*/
