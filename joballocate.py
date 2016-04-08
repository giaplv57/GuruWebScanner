#!/usr/bin/python
import threading
import MySQLdb
import subprocess
import os
import time
import gc
import json

#CHANGE ON DEMAND
WORKER_NUMBER = 10;
DBServer = "localhost"
DBUsername = "root"
DBPassword = "root"

KBOLD = '\033[1m'
KRED = '\x1B[31m'
KCYAN = '\x1B[36m'
KGREEN = '\x1B[32m'
KYELLOW = '\x1B[33m'
KNORM = '\033[0m'

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


def try_connect():
    try:
        conn = MySQLdb.connect(DBServer, DBUsername, DBPassword, "guruWS")
    except:
        return False

    return True;

def welcome():
    if try_connect():
        print green("[+] Connected to database !\n\n")
    else:
        print red("[+] Can't connect to database !")
        exit(0)

    print yellow("\n\tWelcome to joballocate module of GuruWS.")
    print yellow("\tYou should run this program with sudo priviledge")
    print yellow("\n\t@GuruWS Team\n\n") 


def malwr_scan(projectID):
    def taint_analysis():
        uncompressFolder = "./../../../../userProjects/" + projectID + "/"
        outFile = "./../../../../userProjects/" + projectID + ".ta"    
        command = r"""cd ./core/grMalwrScanner/lib/taintanalysis/ ; php main.php {0} {1}""".format(uncompressFolder, outFile)
        subprocess.call(command,shell=True)
        return 0


    
    taint_analysis()

    print cyan("[+] Scanning project...\t" + projectID)

    # Have to make new connection in every thread to avoid 
    # of race condition when dbName.commit() function is excuted
    uncompressFolder = "./../../userProjects/" + projectID + "/"
    conn = MySQLdb.connect(DBServer, DBUsername, DBPassword, "guruWS")
    cursor = conn.cursor()
    
    command = r"""cd ./core/grMalwrScanner/ ; python main.py -q -p blacklist.yara -d {0} --projectid {1}""".format(uncompressFolder, projectID)
    subprocess.call(command,shell=True)
    cursor.execute('UPDATE scanProgress SET sigStatus = "1" WHERE projectID="'+projectID+'"')
    conn.commit()
    
    cursor.close()
    conn.close()


def vuln_scan(projectID):
    print cyan("[+] Scanning project...\t" + projectID)

    # Have to make new connection in every thread to avoid 
    # of race condition when dbName.commit() function is excuted
    conn = MySQLdb.connect(DBServer, DBUsername, DBPassword, "guruWS")
    cursor = conn.cursor()
    uncompressFolder = "./../../userProjects/" + projectID + "/"
    
    command = r"""cd ./core/grVulnScanner/ ; find {0} -name '*.php' | while read LINE; do php Main.php "$LINE" "{1}" & PID=$!; sleep 3s; kill $PID; done""".format(uncompressFolder, projectID)
    subprocess.call(command,shell=True)
    cursor.execute('UPDATE scanProgress SET vulStatus = "1" WHERE projectID="'+projectID+'"')
    
    conn.commit()
    cursor.close()
    conn.close()


def scan_func(projectID):
    malwr_scan(projectID)
    vuln_scan(projectID)


def get_project_to_scan():
    # Have to make new connection in every while loop because
    # of the connection time limitation of DBMS
    conn = MySQLdb.connect(DBServer, DBUsername, DBPassword, "guruWS")
    cursor = conn.cursor()

    # execute SQL query using execute() method.
    cursor.execute("SELECT projectID FROM scanProgress WHERE vulStatus='-1' AND sigStatus='-1' LIMIT 1")

    # Fetch a single row using fetchone() method.
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result


def update_project_status(projectID):
    conn = MySQLdb.connect(DBServer, DBUsername, DBPassword, "guruWS")
    cursor = conn.cursor()
    cursor.execute('UPDATE scanProgress SET vulStatus = "0", sigStatus = "0" WHERE projectID="'+projectID+'"')
    conn.commit()
    cursor.close()
    conn.close()
    return True


if __name__ == '__main__':
    welcome()
    while(True):
        if threading.activeCount() > 10:
            time.sleep(30) #sleep for 1/2 minute
            continue
        else:
            time.sleep(5) #ease the fight (although there won't have any race condition here)
        print green("[+] The number of active threads:\t" + str(threading.activeCount()))

        project_to_scan = get_project_to_scan()

        if project_to_scan != None:
            projectID = project_to_scan[0]
            update_project_status(projectID)
            t = threading.Thread(target=scan_func, args=(projectID,))
            t.start()

        gc.collect() #For a better garbage all the closed connections
