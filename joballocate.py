#!/usr/bin/python
import threading
import MySQLdb
import subprocess
import os
import time
import gc

WORKER_NUMBER = 10;

def vulScan(projectID):
    #Have to make new connection in every thread to avoid 
    # of race condition when dbName.commit() function is excuted
    childConnection = MySQLdb.connect("localhost","root","root","guruWS")
    cursor = childConnection.cursor()
    uncompressFolder = "./userProjects/" + projectID + "/"
    gmsFile = "./userProjects/" + projectID + ".gms"

    command = r"""python ./core/grMalwrScanner/main.py -q -p ./core/grMalwrScanner/patterndb.yara -d {0} -o {1}""".format(uncompressFolder, gmsFile)
    subprocess.call(command,shell=True)
    cursor.execute('UPDATE scanProgress SET sigStatus = "1" WHERE projectID="'+projectID+'"')
    childConnection.commit()

    command = r"""find {0} -name '*.php' | while read LINE; do php ./core/grVulnScanner/Main.php "$LINE" "{1}" & PID=$!; sleep 3s; kill $PID; done""".format(uncompressFolder, projectID)
    subprocess.call(command,shell=True)
    cursor.execute('UPDATE scanProgress SET vulStatus = "1" WHERE projectID="'+projectID+'"')
    
    childConnection.commit()
    cursor.close()
    childConnection.close()

while(True):
    if threading.activeCount() > 10:
        time.sleep(30) #sleep for 1/2 minute
        continue
    else:
        time.sleep(5) #ease the fight (although there won't have any race condition here)
    print threading.activeCount()    
    #Have to make new connection in every while loop because
    # of the connection time limitation of DBMS
    mainConnection = MySQLdb.connect("localhost","root","root","guruWS")
    cursor = mainConnection.cursor()

    # execute SQL query using execute() method.
    cursor.execute("SELECT projectID FROM scanProgress WHERE vulStatus='-1' AND sigStatus='-1' LIMIT 1")
    # Fetch a single row using fetchone() method.
    result = cursor.fetchone()

    if result != None:
        projectID = result[0]
        cursor.execute('UPDATE scanProgress SET vulStatus = "0", sigStatus = "0" WHERE projectID="'+projectID+'"')
        mainConnection.commit()
        t = threading.Thread(target=vulScan, args=(projectID,))
        t.start()
    cursor.close()    
    mainConnection.close()
    gc.collect() #For a better garbage all the closed connections
