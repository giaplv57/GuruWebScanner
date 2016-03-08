<?php
class TestClass {

    public $a;
    private $c;

    public function set($arg1) {
        $this->a = $arg1;
    }

    public function get() {
        return $this->a;
    }

}

$a = new TestClass();
$a->set($_POST["a"]);
echo $a->get();


$b = new TestClass();
$b->a = $_POST["b"];
echo $b->get();

$c = new TestClass();
$c->set($_POST["c"]);
echo $c->a;
