"""
    Scan file, using .yara file

    @GuruTeam

"""

import optparse
import sys
import os
import hashlib
import yara
import json

KBOLD = '\033[1m'
KRED = '\x1B[31m'
KCYAN = '\x1B[36m'
KGREEN = '\x1B[32m'
KYELLOW = '\x1B[33m'
KNORM = '\033[0m'

QUITEMODE   = False
PATTERNDB   = 'patterndb.yara'
dfuncs      = ["preg_replace", "passthru", "shell_exec", "exec", "base64_decode", "eval", "system", "proc_open", "popen", "curl_exec", "curl_multi_exec", "parse_ini_file", "show_source"]

_shells     = []
_dfuncs     = []

def bold(text):
    return KBOLD + text + KNORM

def cyan(text):
    return KCYAN + text + KNORM

def green(text):
    return KGREEN + text + KNORM

def red(text):
    return KRED + text + KNORM

def yellow(text):
    return KYELLOW + text + KNORM

def nocolor(text):
    return text

def hide(filename): 
    if not 'userFiles' in filename:
        return filename
    return filename.split('userFiles')[1]


def gateway():
    parser = optparse.OptionParser()
    parser.add_option('--directory', '-d', type="string", help="specify directory to scan")
    parser.add_option('--filename', '-f', type="string", help="specify file to scan")
    parser.add_option('--outfile', '-o', type="string", help="specify outfile to write result using JSON")
    parser.add_option('--patterndb', '-p', type="string", help="specify patterndb file")
    parser.add_option('--quite', '-q', default=False, action="store_true", help="enable quite mode")
    
    (options, args) = parser.parse_args()

    if len(sys.argv) == 1:        
        parser.print_help()
        exit()

    return options, args, options.quite

def scan_dangerous_function(content, url, filename):
    lines = content.split('\n')
    for lineno in range(0, len(lines)):
        for dfunc in dfuncs:
            if dfunc in lines[lineno]:
                print red( "[+] Found dangerous function\t: " + dfunc + " in " + hide(url) + "[" + str(lineno) + "]" )
                tfunc = {
                    "function": dfunc,
                    "url": url[53:],
                    "line": lineno,
                    "filename": filename
                }
                _dfuncs.append(tfunc)
    return 0


def export_to_outfile(outfile):
    with open(outfile, "wb") as f:
        f.write(json.dumps({"webshell":_shells, "dfunc":_dfuncs}))
    print green("[+] Saved results to:\t" + outfile)



if __name__ == '__main__':
    options, args, QUITEMODE = gateway()

    if options.patterndb != None:
        PATTERNDB = options.patterndb

    rules = yara.compile(PATTERNDB)
    
    file_count = 0
    shell_count = 0

    if options.filename != None:
        filename = options.filename
        if not QUITEMODE:
            print cyan("[+] Scanning...\t"), cyan(filename)
            
        matches = rules.match(filename)
        if matches != []:
            print red("[+] Found...\t"), red(str(matches[0])), red("\tin (") + red(hide(filename)) + red(")")
        else:
            print yellow("[+] Great ! Nothing found, or something went wrong :)")

    if options.directory != None:
        rootDir = options.directory
        for dirName, subdirList, fileList in os.walk(rootDir):            
            for fname in fileList:
                filename = dirName + '/' + fname      # get absolute filename                

                file_count += 1
                if not QUITEMODE:
                    print cyan("[+] Scanning...\t"), cyan(hide(filename))
                with open(filename, 'rb') as f:
                    d = f.read()
                if len(d) == 0:
                    continue
                
                matches = rules.match(filename)
                if matches != []: 
                    shell_count += 1
                    shellname = str(matches[0])
                    print red("[+] Found...\t"), red(shellname), red("\tin (") + red(hide(filename)) + red(")")                    
                    tshell = {
                        "shellname": shellname,
                        "url": filename[53:],
                        "filename": fname                        
                    }
                    _shells.append(tshell)
                else:
                    scan_dangerous_function(d, filename, fname)            # just scan dangerous function with the file, which is not be detect as shellcode
        print green("[+] Analized\t: " + str(file_count) + " files ")
        if shell_count != 0:
            print green("[+] Found\t: " + str(shell_count) + " shells ")
        else:
            print yellow("[+] Great ! Nothing found, or something went wrong :)")
        
        if options.outfile != None:
            export_to_outfile(options.outfile)     # just export when scan directory


""" JSON struct:

    {
        "dfunc":
            [{
                "function": "lolololol",
                "filename": "passwd",
                "url": "/etc/passwd",
                "line": 0
                }]
        ,
        "webshell":
            [{
                "shellname": "lololol0l",
                "url": "/bin/sh",
                "filename": "sh"
                }]

        }


"""
