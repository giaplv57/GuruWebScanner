"""
    Scan file, using .yara file

    @GuruTeam

"""

import optparse
import sys
import os
import subprocess
import hashlib
import yara
import json
import MySQLdb
import base64
from config.general import *

#CHANGE ON DEMAND


KBOLD = '\033[1m'
KRED = '\x1B[31m'
KCYAN = '\x1B[36m'
KGREEN = '\x1B[32m'
KYELLOW = '\x1B[33m'
KNORM = '\033[0m'

PATTERNDB = 'config/pm_blacklist.yara'      # default value

_shells     = []
_dfuncs     = []
_urllist  = []

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
    parser.add_option('--projectid', '-i', type="string", help="specify project ID")
    parser.add_option('--dispm', '-n', default=False, action="store_true", help="disable patterm matching module")
    parser.add_option('--quite', '-q', default=False, action="store_true", help="enable quite mode")
    
    (options, args) = parser.parse_args()

    if len(sys.argv) == 1:        
        parser.print_help()
        exit()

    return options, args, options.quite


def line_reduce(linecontent):
    MAXLINESIZE = 200
    if len(linecontent) > MAXLINESIZE:
        return linecontent[:MAXLINESIZE] + "..."
    else:
        return linecontent

def check_php_lib():
    try:
        process = subprocess.Popen(['php', '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
    except Exception, e:
        print e
        return False

    if "PHP 5." in stdout[:10]:
        return True
    else:
        return False

def import_shell(url, shellname, filename, filesize=0, line='?', sink='????'):
    _urllist.append(url);
    tshell = {
        "shellname": shellname,
        "url": url,
        "filename": filename,
        "filesize": filesize,
        "line": line,
        "sink": sink
    }
    _shells.append(tshell)

def scan_dangerous_function(content, url, filename):
    lines = content.split('\n')
    for lineno in range(0, len(lines)):
        for dfunc in dfuncs:
            if dfunc in lines[lineno]:
                print red( "[+] Found dangerous function\t: " + dfunc + " in " + hide(url) + "[" + str(lineno) + "]" )
                tfunc = {
                    "function": dfunc,
                    "url": url[61:],
                    "lineno": lineno,
                    "line": base64.b64encode(line_reduce(lines[lineno])),
                    "filename": filename,
                    "filesize": len(content)
                }
                _dfuncs.append(tfunc)
    return 0


def export_to_outfile(outfile):
    try:
        with open(outfile, "wb") as f:
            f.write(json.dumps({"webshell":_shells, "dfunc":_dfuncs}, ensure_ascii=False))
        print green("[+] Saved results to:\t" + outfile)
    except Exception, e:
        print "Error when try to save malResult to " + outfile
        raise Exception, e


def write_to_DB(projectid):
    try:
        dbConnection = MySQLdb.connect(DBServer, DBUsername, DBPassword, DBname)
        cursor = dbConnection.cursor()
        query = "INSERT INTO malResult (projectID, result) VALUES (%s, %s)"
        cursor.execute(query, (projectid, json.dumps({"webshell":_shells, "dfunc":_dfuncs}, ensure_ascii=False)))
        dbConnection.commit()
        cursor.close()
        dbConnection.close()
        print green("[+] Saved results to database")
    except Exception, e:
        print "Error when try to save malResult to DB"
        raise Exception, e


def load_taint_analysis_result(projectid):
    def get_json_content():
        try:
            if projectid != None:
                outfile = "./../../userProjects/" + projectid + ".ta"
            else:
                outfile = '.taintanalysis-output.ta'
            with open(outfile, 'r') as f:
                output = f.read()
            return json.loads(output)
        except:
            return None
    
    print green('\n\n[ ----- Taint Analysis result ----- ]')

    json_content = get_json_content()

    if json_content is None:
        print "Taint Analysis: no result"
        return True            

    for key, values in json_content.iteritems():
        #key = key.replace('//', '/')
        #print key

        filename = key
        for value in values:
            treenodes = value['treenodes']
            for treenode in treenodes: 
                if len(key) > 60:
                    url = key[61+4:]                
                else:
                    url = key
                    print cyan("Url: " + url[3:])                    
                if not url in _urllist:                     
                    shellname = "GuruWS :: Taint Analysis :: " + treenode['title']
                    #line = treenode['value'].split('>')[1].split(':')[0]
                    line = treenode['value'].split(': ')[1]
                    filename = key.split('/')[-1]
                    filesize = 0
                    sink = treenode['name']                                   
                    import_shell(url, shellname, filename, filesize, line, sink)                    
    print _shells
    return True


def taint_analysis(projectid, directory):    

    if not directory[0] == '/':
        directory = '../' + directory

    if projectid == None:
        outFile = "../.taintanalysis-output.ta"    
        command = r"""cd lib/ ; php taintanalysis.php {0} {1}""".format(directory, outFile)
        subprocess.call(command,shell=True)
        return 0
    else:
        uncompress_folder = "./../../../userProjects/" + projectid + "/"
        outFile = "./../../../userProjects/" + projectid + ".ta"    
        command = r"""cd lib/ ; php taintanalysis.php {0} {1}""".format(uncompress_folder, outFile)
        subprocess.call(command,shell=True)
        return 0


def show_result(file_count, shell_count):
    print green("\n\n[ -----  Pattern matching result  ----- ]")
    print yellow("[+] Analized\t: " + str(file_count) + " files ")
    if shell_count != 0:
        print yellow("[+] Found\t: " + str(shell_count) + " shells ")
    else:
        print yellow("[+] Great ! Nothing found, or something went wrong :)")

    for shell in _shells:
        print shell
        print cyan("[+] Found...\t" + shell['shellname'] + " " + "\tin (" + shell['filename'] + ")")                    


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
        if rootDir[-1] != '/':
            rootDir += '/'
        taint_analysis(options.projectid, options.directory)

        if not options.dispm:
            for dirName, subdirList, fileList in os.walk(rootDir):    
                if dirName[-1] != '/':
                    dirName += '/'        
                for fname in fileList:
                    filename = dirName + fname      # get absolute filename                
                    file_count += 1

                    if not QUITEMODE:
                        print cyan("[+] Scanning...\t"), cyan(hide(filename))

                    with open(filename, 'rb') as f:
                        filecontent = f.read()

                    if len(filecontent) == 0:
                        continue
                    
                    matches = rules.match(filename)
                    url = filename[61:]                
                    if matches != [] and not url in _urllist: 
                        shell_count += 1
                        shellname = str(matches[0])                    
                        filesize = len(filecontent)
                        import_shell(url, shellname, fname, filesize)                    
                        #print cyan("[+] Found...\t"), red(shellname), red("\tin (") + red(hide(filename)) + red(")")                    
                    else:
                        scan_dangerous_function(filecontent, filename, fname)            # just scan dangerous function with the file, which is not be detect as shellcode
            
            show_result(file_count, shell_count)        

        load_taint_analysis_result(options.projectid)

        if options.outfile != None:
            export_to_outfile(options.outfile)     # just export when scan directory
        if options.projectid != None:
            write_to_DB(options.projectid)

""" JSON struct:

    {
        "dfunc":
            [{
                "function": "lolololol",
                "filename": "passwd",
                "url": "/etc/passwd",
                "lineno": 0,
                "line": 0,
                "filesize": 122
                }]
        ,
        "webshell":
            [{
                "shellname": "lololol0l",
                "url": "/bin/sh",
                "filename": "sh",
                "filesize": 11
                }]

        }


"""
