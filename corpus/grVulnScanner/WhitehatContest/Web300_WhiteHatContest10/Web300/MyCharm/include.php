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
    function ConnectDB(){
        $db_username="root";
        $db_password="root";
        $database="luckynumber";
        $con=mysqli_connect('127.0.0.1', $db_username, $db_password, $database);
        return $con;
    }
?>