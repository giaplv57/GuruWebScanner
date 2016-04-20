<?php
    include('config/ta_general.php');          // general settings
    include('config/ta_sources.php');          // tainted variables and functions
    include('config/ta_tokens.php');           // tokens for lexical analysis
    include('config/ta_securing.php');         // securing functions
    include('config/ta_sinks.php');            // sensitive sinks
    include('config/ta_info.php');             // interesting functions    
    
    include('lib/ta_constructer.php');         // classes  
    include('lib/ta_filer.php');               // read files from dirs and subdirs
    include('lib/ta_tokenizer.php');           // prepare and fix token list
    include('lib/ta_string_analyzer.php');     // string analyzers
    include('lib/ta_scanner.php');             // provides class for scan
    include('lib/ta_printer.php');             // output scan result
    include 'lib/ta_debug.php';                // for debugging
 
    $scan_functions = array(); 
    $scan_functions = array_merge(
                        $F_CODE,                        
                        $F_EXEC,                        
                        $F_XPATH                   
                    );
    $info_functions = Info::$F_INTEREST;
    $source_functions = Sources::$F_OTHER_INPUT;
    
    $url = $argv[1];
    $outfile = $argv[2];

    if (is_dir($url)) {
        $files = read_recursiv($url);
    }
    else if (is_file($url)) {        
        $files[0] = $url;
    }
    else {
        $files = array();
    }

    if (count($files) == 0) {
        debug_red('Something wrong. The number of scanned files: ' . count($files) . ' at ' . $url);
        die();
    }

    for($fi=0; $fi < count($files); $fi++) {        
        $scan = new Scanner($files[$fi], $scan_functions, $info_functions, $source_functions);   
        $scan->parse();
    }

    $result = json_encode($GLOBALS['output']);
    $freport = fopen($outfile,"w");
    fwrite($freport, $result);
    fclose($report);

?>