<?php
    include('config/general.php');          // general settings
    include('config/sources.php');          // tainted variables and functions
    include('config/tokens.php');           // tokens for lexical analysis
    include('config/securing.php');         // securing functions
    include('config/sinks.php');            // sensitive sinks
    include('config/info.php');             // interesting functions    
    
    include('lib/constructer.php');         // classes  
    include('lib/filer.php');               // read files from dirs and subdirs
    include('lib/tokenizer.php');           // prepare and fix token list
    include('lib/analyzer.php');            // string analyzers
    include('lib/scanner.php');             // provides class for scan
    include('lib/printer.php');             // output scan result
    include('lib/searcher.php');            // search functions
    include 'lib/debug.php';
 
    $scan_functions = array();
    $scan_functions = array_merge(
                        $F_XSS,
                        $F_HTTP_HEADER,
                        $F_SESSION_FIXATION,
                        $F_CODE,
                        $F_REFLECTION,
                        $F_FILE_READ,
                        $F_FILE_AFFECT,
                        $F_FILE_INCLUDE,
                        $F_EXEC,
                        $F_DATABASE,
                        $F_XPATH,
                        $F_LDAP,
                        $F_CONNECT,
                        $F_POP,
                        $F_OTHER
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
        $scan = new Scanner($files[$fi], $scan_functions, $info_functions, $source_functions);   //* call Scanner
        $scan->parse();
    }

    // save result to json file
    $result = json_encode($GLOBALS['output']);
    
    $freport = fopen($outfile,"w");
    fwrite($freport, $result);
    fclose($report);
    
?>