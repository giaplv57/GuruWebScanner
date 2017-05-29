 <?php 
  $a = $_GET["a"];
  system(testFunc($a));

  function testFunc($arg) {
      echo $arg;
      return $arg;
  }
  #RIPS just detect command inject
  #THAP: just detect XSS
  #E-THAPS: 2 vuls
?>