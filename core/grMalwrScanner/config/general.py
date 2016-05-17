import json

#:: Database information
# DBCONFIGFILE = '/var/www/html/guruws/dbconfig/db.cfg'
DBCONFIGFILE = '../../dbconfig/db.cfg'
try:
    with open(DBCONFIGFILE) as configfile:         
        dbconf = json.load(configfile)        
    DBServer = dbconf['server']
    DBUsername = dbconf['username']
    DBPassword = dbconf['password']
    DBname = dbconf['name']    
except:    
    raise Exception, DBCONFIGFILE + " not found or coule be damaged !"


#:: Display
QUITEMODE   = False

#:: Pattern
PATTERNDB   = 'lib/patternmatching/blacklist.yara'

#:: dangeous function
dfuncs      = ["preg_replace", "passthru", "shell_exec", "exec", "base64_decode", "eval", "system", "proc_open", "popen", "curl_exec", "curl_multi_exec", "parse_ini_file", "show_source"]
