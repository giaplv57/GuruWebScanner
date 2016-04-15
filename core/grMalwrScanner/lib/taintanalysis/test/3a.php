<?php
function mfunc($x) {
    return $x;
}
$y = mfunc($_GET['scsc']);
system($y);
?>

    
// traces recursivly parameters and adds them as child to parent
// returns true if a parameter is tainted by userinput (1=directly tainted, 2=function param)