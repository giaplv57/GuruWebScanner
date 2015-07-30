<?php
$a = mysql_real_escape_string($_POST["a"]);
mysql_query("SELECT '$a' FROM $a");
