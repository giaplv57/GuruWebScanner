<?php
  $con=mysqli_connect('localhost', 'root', 'root', 'testDatabase');
  $a = $_GET["a"];
  $b = mysqli_escape_string($con, $a);
  mysqli_query($con, "SELECT * FROM reports WHERE name='$a'");
  mysqli_query($con, "SELECT * FROM reports WHERE id='$b'");
  mysqli_query($con, "SELECT * FROM reports WHERE id=$b");

  #RIPS AND E-THAPS FOUND 2
  #THAPS FOUND 0
?>