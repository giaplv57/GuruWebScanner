<?php
  $a = $_POST["a"];
  print (cleanFunc($a));

  function cleanFunc($arg) {
      return htmlentities($arg);
  }
  #THAP AND E-THAPS : 0 vul
  #RIP false positive : 1 vul
?>