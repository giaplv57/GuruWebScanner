#:: Database information
DBServer = "localhost"

DBUsername = "root"

DBPassword = "root"

#:: Display
QUITEMODE   = False

#:: Pattern
PATTERNDB   = 'lib/patternmatching/blacklist.yara'

#:: dangeous function
dfuncs      = ["preg_replace", "passthru", "shell_exec", "exec", "base64_decode", "eval", "system", "proc_open", "popen", "curl_exec", "curl_multi_exec", "parse_ini_file", "show_source"]
