<?php  
  $x = $_POST["x"];
  $y = mysql_real_escape_string($x);
  mysql_query("SELECT * FROM reports WHERE name='$x'");
  mysql_query("SELECT * FROM reports WHERE id='$y'");
  mysql_query("SELECT * FROM reports WHERE id=$y");

  #RIPS AND E-THAPS FOUND 2
  #THAPS FOUND 2
?>