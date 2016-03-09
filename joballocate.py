#!/usr/bin/python
import threading
import MySQLdb
import subprocess
import os
import time
import gc

WORKER_NUMBER = 10;

def vulScan(newFilename):
    #Have to make new connection in every thread to avoid 
    # of race condition when dbName.commit() function is excuted
    childConnection = MySQLdb.connect("localhost","root","root","guruWS")
    cursor = childConnection.cursor()
    uncompressFolder = "./userFiles/" + newFilename + "/"
    resultFile = "./userFiles/" + newFilename + ".result"
    print uncompressFolder
    command = r"""find {0} -name '*.php' | while read LINE; do php ./core/grVulnScanner/Main.php "$LINE" & PID=$!; sleep 3s; kill $PID; done > {1}""".format(uncompressFolder, resultFile)
    subprocess.call(command,shell=True)

    command = r"""python ./core/grMalwrScanner/main.py -q -p ./core/grMalwrScanner/patterndb.yara -d {0} -o {1}.gms""".format(uncompressFolder, resultFile)
    subprocess.call(command,shell=True)

    cursor.execute('UPDATE vulScanProgress SET status = "1" WHERE newFilename="'+newFilename+'"')
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
    cursor.execute("SELECT newFilename FROM vulScanProgress WHERE status='-1' LIMIT 1")
    # Fetch a single row using fetchone() method.
    result = cursor.fetchone()

    if result != None:
        newFilename = result[0]
        cursor.execute('UPDATE vulScanProgress SET status = "0" WHERE newFilename="'+newFilename+'"')
        mainConnection.commit()
        t = threading.Thread(target=vulScan, args=(newFilename,))
        t.start()
    cursor.close()    
    mainConnection.close()
    gc.collect() #For a better garbage all the closed connections
