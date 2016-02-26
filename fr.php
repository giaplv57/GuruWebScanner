<?php
if ('0e69' == '0e122') {
    echo "Matched.\n";
}

$secret = "{CENSORED}";

if ($_COOKIE["auth"] && $_COOKIE["sign"]) {
    echo $_COOKIE["auth"];
    echo '---';
    echo $_COOKIE["sign"];
    echo '---';
    echo 'sha='.sha1($secret . $_COOKIE["auth"]);
    echo '---';    
    echo strpos($_COOKIE["auth"], "framgia2016");
    echo '---';
    if (sha1($secret . $_COOKIE["auth"]) == $_COOKIE["sign"]) {
        print 'ddd';
    }
    echo '---';
    if (sha1($secret . $_COOKIE["auth"]) == $_COOKIE["sign"] && strpos($_COOKIE["auth"], "framgia2016") === 0) {
        echo "Good, {CENSORED}";
    } else {
        echo "Bad";
    }
} else {
    echo 'Bad';
}
?>
<html>
    <h1>Can you get the flag ? hehehehe</h1>
</html>
<!-- index.phps -->