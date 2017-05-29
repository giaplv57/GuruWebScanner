<?php
  function NotSanitized($string){
      return $string;
  }
  function ImproperSanitized($string){
      return htmlentities($string);
  }
  function ProperSanitized($string){
      return escapeshellcmd($string);
  }
  print (NotSanitized($_GET['1']));
  print (ImproperSanitized($_GET['2']));
  print (ProperSanitized($_GET['3']));
  #RIPS FOUND FIRST VUL
  #THAP AND E-THAPS FOUND FIRST AND SECOND
?>