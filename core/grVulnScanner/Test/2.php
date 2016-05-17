<?php
if (true) {
    $a = $_POST["a"];
} else {
    $a = $_POST["b"];
}
if ($a !== "") {
    $a = htmlentities($a);
}else {
    $a = "Can not be blank!!";
}
echo $a;
#THAP AND E-THAP NOT VULS
#RIP 1 XSS VULS
?>