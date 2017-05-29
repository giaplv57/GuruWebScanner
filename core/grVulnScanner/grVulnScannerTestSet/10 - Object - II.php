<?php
  class TestClass {
    public static function sanitizerCommandInjection($arg) {
      return escapeshellarg($arg);
    }
    public static function sanitizerXSS($arg) {
      return htmlentities($arg);
    }
    public function sanitizer1($arg) {
      return TestClass::sanitizerCommandInjection($arg);
    }
    public function sanitizer2($arg) {
      return TestClass::sanitizerXSS($arg);
    }
  }
  $test = new TestClass();
  echo $test->sanitizer1($_GET['1']);
  echo $test->sanitizer2($_GET['2']);
  #THAPS AND E-THAPS FOUND 1 XSS
  #RIPS FOUND 2 XSS : 1 FP
?>