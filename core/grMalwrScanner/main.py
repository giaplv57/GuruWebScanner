"""
    Scan file, using .yara file

    @GuruTeam

"""

import optparse
import sys
import os
import hashlib
import yara

KBOLD = '\033[1m'
KRED = '\x1B[31m'
KCYAN = '\x1B[36m'
KGREEN = '\x1B[32m'
KYELLOW = '\x1B[33m'
KNORM = '\033[0m'

QUITEMODE   = False
PATTERNDB   = 'patterndb.yara'

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


def gateway():
    parser = optparse.OptionParser()
    parser.add_option('--directory', '-d', type="string", help="specify directory to scan")
    parser.add_option('--filename', '-f', type="string", help="specify file to scan")
    parser.add_option('--quite', '-q', default=False, action="store_true", help="enable quite mode")
    
    (options, args) = parser.parse_args()

    if len(sys.argv) == 1:        
        parser.print_help()
        exit()

    return options, args, options.quite


if __name__ == '__main__':
    options, args, QUITEMODE = gateway()

    rules = yara.compile(PATTERNDB)
    
    file_count = 0
    shell_count = 0

    if options.filename != None:
        filename = options.filename
        if not QUITEMODE:
            print cyan("[+] Scanning...\t"), cyan(filename)
            
        matches = rules.match(filename)
        if matches != []:
            print red("[+] Found...\t"), red(str(matches[0])), red("\tin (") + red(filename) + red(")")
        else:
            print yellow("[+] Great ! Nothing found, or something went wrong :)")
    if options.directory != None:
        rootDir = options.directory
        for dirName, subdirList, fileList in os.walk(rootDir):            
            for fname in fileList:
                filename = dirName + '/' + fname      # get absolute filename
                file_count += 1
                if not QUITEMODE:
                    print cyan("[+] Scanning...\t"), cyan(filename)            
                with open(filename, 'rb') as f:
                    d = f.read()
                if len(d) == 0:
                    continue
                matches = rules.match(filename)
                if matches != []: 
                    shell_count += 1
                    print red("[+] Found...\t"), red(str(matches[0])), red("\tin (") + red(filename) + red(")")
        print green("[+] Analized\t: " + str(file_count) + " files ")
        if shell_count != 0:
            print green("[+] Found\t: " + str(shell_count) + " shells ")
        else:
            print yellow("[+] Great ! Nothing found, or something went wrong :)")
