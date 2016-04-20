"""
    -- [ Export signatures from found webshell to .yara file ] ------

                                                            @GuruTeam

"""

import optparse
import sys
import os
import hashlib
import base64
import random

SIGNATURE_LENGTH = 64
SIGNATURE_NUMBER = 5
MIN_UNIQUE_CHARACTER = 5

KBOLD = '\033[1m'
KRED = '\x1B[31m'
KCYAN = '\x1B[36m'
KGREEN = '\x1B[32m'
KYELLOW = '\x1B[33m'
KNORM = '\033[0m'
yarafile = None

shelllib = []       # avoid duplicated shellname

def out(s):
    try:
        yarafile.write(s)
    except:
        raise Exception, "Check --output file"

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
    parser.add_option('--directory', '-d', type="string", help="specify directory containing Web Shell to import")
    parser.add_option('--filename', '-f', type="string", help="specify Web Shell file to import")
    parser.add_option('--output', '-o', type="string", help="specify .yara output file")
    
    (options, args) = parser.parse_args()

    if len(sys.argv) == 1 or options.output == None:        
        parser.print_help()
        exit()

    global yarafile
    yarafile = open(options.output, 'w')    
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
    
    if n < 50 or filename.lower()[-3:] == '.md' or "readme" in filename.lower()  or "copyright" in filename.lower() or "license" in filename.lower() or "copying" in filename.lower() or "gpl" in filename.lower():             # if file is too small or readme.md, ignore ... avoid False Positive
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
    shellname = shellname.replace(',', '_')
    shellname = shellname.replace(' ', '_')
    shellname = shellname.replace('(', '_')
    shellname = shellname.replace(')', '_')
    shellname = shellname.replace(']', '_')
    shellname = shellname.replace('[', '_')
    shellname = shellname.replace('#', '_')
    shellname = shellname.replace('$', '_')
    shellname = shellname.replace('@', '_')
    shellname = shellname.replace('!', '_')
    shellname = shellname.replace('^', '_')
    shellname = shellname.replace('*', '_')
    shellname = shellname.replace('=', '_')
    shellname = shellname.replace('{', '_')
    shellname = shellname.replace('}', '_')
    shellname = shellname.replace('\'', '_')
    shellname = shellname.replace('%', '_')

    if shellname in shelllib:
        shellname = shellname + '_' + str(random.randint(0, 100000))
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
    #out('\t\t any of them\n')
    out('\t\t' + str(len(strings)/2 + 1) + ' of them\n')
    out('}\n\n')


def export_from_webshell():
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


def export_from_shelldetectdb():
    def tohex(s):
        return " ".join("{:02x}".format(ord(c)) for c in s)

    with open('res/shelldetect.db', 'rb') as f:
        d = f.read()

    d = base64.b64decode(d)

    lines = d.split(']\"')
    
    for line in lines:
        b = line.split('\"')
        try:
            sign = b[1]
            shellname = b[3]
            if shellname == 'version' or len(sign) < 12:
                continue
        except:
            continue

        shellname = 'SHELLDETECT_' + shellname
        export(shellname, [sign])


    f.close()


def export_from_pmf():
    try:
        with open('res/pmf.yara') as f:
            pmf_content = f.read()
        out(pmf_content)  
    except:        
        print red("[+] Can't open res/pmf.yara => Unable to export patterns from pmf content")
        return False   
    return True

def export_whitelist():
    out('include "whitelist.yara"\n\n')


if __name__ == '__main__':

    # export_whitelist()

    export_from_webshell()
    export_from_shelldetectdb()
    
    print cyan('[+] ' + str(len(shelllib)) + " patterns were exported !")

    if export_from_pmf():
        print cyan('[+] Patterns from php-malware-finder were exported !')        

try:
    yarafile.close()
except:
    raise Exception, "Can't close the outfile"
