<?php
//$con=mysqli_connect('localhost', $db_username, $db_password, $database);
$db_username="root";
$db_password="root";
$database="guruWS";
$con = mysqli_connect('localhost', $db_username, $db_password, $database);
$a = $_GET["a"];
$result = mysql_query($con, "SELECT * from reports where shareID=$a");
