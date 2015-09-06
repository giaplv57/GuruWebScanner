<?php
    function ConnectDB(){
        $db_username="root";
        $db_password="root";
        $database="guruWS";
        $con=mysqli_connect('localhost', $db_username, $db_password, $database);
        return $con;
    }
?>
