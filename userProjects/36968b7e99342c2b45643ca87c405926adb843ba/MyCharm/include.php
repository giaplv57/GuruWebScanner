<!doctype html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Lucky Number!</title>
        <!-- CSS -->
        <link rel="stylesheet" href="assets/bootstrap/dist/css/bootstrap.css">
        <link rel="stylesheet" href="assets/font-awesome/css/font-awesome.css">
        <link rel="stylesheet" href="assets/css/business-casual.css">          
        <link rel="stylesheet" href="assets/css/charmButton.css">          
        <!-- JS -->
        <script src="assets/bootstrap/dist/bootstrap.js"></script>
    </head>
</html>

<?php
    error_reporting(E_ALL);
    function ConnectDB(){
        $db_username="root";
        $db_password="root";
        $database="luckynumber";
       	$con=mysql_connect('127.0.0.1', $db_username, $db_password);
	$con_select = mysql_select_db($database, $con);
        return $con;
    }
?>
