
<?php

function debug( $data ) {

    if ( is_array( $data ) ) {
        $output = "<script>console.log( 'Debug Objects: " . implode( ',', $data) . "' );</script>";    
    }
    else
        $output = "<script>console.log( 'Debug Objects: " . $data . "' );</script>";

    echo $output;
}

function debug_normal( $data ) {
    echo "\033[1m" . $data . "\n";    
}

function debug_bold( $data ) {
    echo "\033[1m" . $data . "\033[0m" . "\n";    
}

function debug_red( $data ) {
    echo "\x1B[31m" . $data . "\033[0m" . "\n";    
}

function debug_cyan( $data ) {
    echo "\x1B[36m" . $data . "\033[0m" . "\n";    
}

function debug_green( $data ) {
    echo "\x1B[32m" . $data . "\033[0m" . "\n";    
}

function debug_yellow( $data ) {
    echo "\x1B[33m" . $data . "\033[0m" . "\n";    
}

?>