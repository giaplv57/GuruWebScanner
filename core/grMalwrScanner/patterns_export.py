"""
    Export signatures from found webshell to .yara file

    @GuruTeam

"""

import optparse
import sys
import os
import hashlib

SIGNATURE_LENGTH = 64
SIGNATURE_NUMBER = 5
MIN_UNIQUE_CHARACTER = 5

KBOLD = '\033[1m'
KRED = '\x1B[31m'
KCYAN = '\x1B[36m'
KGREEN = '\x1B[32m'
KYELLOW = '\x1B[33m'
KNORM = '\033[0m'
yarafile = open('patterndb.yara', 'w')
shelllib = []       # avoid duplicated shellname


def out(s):
    yarafile.write(s)

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
    parser.add_option('--filename', '-f', type="string", help="specufy file to scan")
    
    (options, args) = parser.parse_args()

    if len(sys.argv) == 1:        
        parser.print_help()
        exit()

    return options, args


def is_whitelist(s):
    """
    avoid False Positive
    """

    def get_unique_character(s):
        uc = []
        for c in s:        
            if not c in uc:
                uc.append(c)
        return len(uc)

    if get_unique_character(s) < MIN_UNIQUE_CHARACTER:            
        return True
    return False


def scanfile(filename):
    """
    exports signatures from filename 's content and saves to strings
    """

    def substr(str, start, length):
        end = start+length
        if end >= len(str):
            raise Exception("Error when get substring")
        return str[start:end]


    print cyan("[+] Scanning...\t"), cyan(filename)
    with open(filename, 'r') as f:
        d = f.read()
    n = len(d)
    
    if n < 50 or filename.lower()[-3:] == '.md':             # if file is too small or readme.md, ignore ... avoid False Positive
        print red("[+] Ignoring...\t"), red(filename), red(str(n))
        return []

    strings = []

    if n < 300:                 # if file small, get whole of content
        strings.append(d)
        return strings
    
    for i in range(SIGNATURE_NUMBER):
        block = (n / (SIGNATURE_NUMBER + 1)) * (i + 1)
        pat = substr(d, block - SIGNATURE_LENGTH, SIGNATURE_LENGTH)
        if not is_whitelist(pat):
            strings.append(pat)
    return strings


def export(shellname, strings):
    """
    export signatures to .yara file
    """

    def tohex(s):
        return " ".join("{:02x}".format(ord(c)) for c in s)

    def is_ascii(s):
        return all(ord(c) < 128 for c in s)


    if len(strings) == 0:
        return 0

    shellname = shellname.split('/')[-1]
    shellname = shellname.replace('.', '_')
    shellname = shellname.replace('-', '_')
    shellname = shellname.replace('+', '_')
    shellname = shellname.replace(' ', '_')
    shellname = shellname.replace('(', '_')
    shellname = shellname.replace(')', '_')
    shellname = shellname.replace(']', '_')
    shellname = shellname.replace('[', '_')
    shellname = shellname.replace('#', '_')
    shellname = shellname.replace('=', '_')
    shellname = shellname.replace('{', '_')
    shellname = shellname.replace('}', '_')
    shellname = shellname.replace('\'', '_')
    shellname = shellname.replace('%', '_')

    if shellname in shelllib:
        return 0
    shelllib.append(shellname)

    print green("[+] Exporting shell...\t"), green(shellname)

    if not is_ascii(shellname):
        shellname = "unknown_" + hashlib.md5(shellname).hexdigest()[:10]
    out('rule SHELL_' + shellname + '\n')
    
    out('{\n')
    out('\tstrings:\n')
    for s in strings:
        if s == '':           
            continue    
        out('\t\t$ = {' + tohex(s)+ '}\n')
    out('\tcondition:\n')
    out('\t\t' + str(SIGNATURE_NUMBER/2) + ' of them\n')
    out('}\n\n')


if __name__ == '__main__':

    options, args = gateway()
    if options.filename != None:
        strings = scanfile(options.filename)
        export(options.filename, strings)
    elif options.directory != None:

        rootDir = options.directory
        for dirName, subdirList, fileList in os.walk(rootDir):            
            for fname in fileList:
                filename = dirName + '/' + fname      # get absolute filename
                strings = scanfile(filename)
                export(filename, strings)

    print cyan('[+] ' + str(len(shelllib)) + " patterns were exported !")
    

yarafile.close()
