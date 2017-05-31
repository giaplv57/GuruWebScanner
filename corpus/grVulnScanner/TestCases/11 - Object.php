<?php
  class TestClass {
      public $a;
      public function set($arg1) {
          $this->a = $arg1;
      }
      public function push() {
          $con = mysqli_connect('localhost', "root", "root", "guruWS");
          mysqli_query($con, "SELECT * from reports where shareID=$this->a");
          return 'Pushed ' . $this->a;
      }
  }
  $test = new TestClass();
  $test->set($_POST["a"]);
  echo $test->push();
  #THAPS AND E-THAPS: 2 vuls
  #RIPS: 0 VULS
?>