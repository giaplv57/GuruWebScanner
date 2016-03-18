#!/usr/bin/env python
# -*- coding: UTF-8 -*- 
##############################################################
# Licence: Copyright (c) 2014 pys0lve <shiqiaomu@me.com>
# Date:    2014/11/14 19:00:00
# Brief:   webshell-checker
# href:    https://github.com/shiqiaomu/webshell-collector
# V1.0     14 Nov 2014 Initial release
###############################################################

"""
check whether the webshell already has been collected
"""

import hashlib
import sys
import os


class Checker(object):
    """
        Some Methods To Check file
        For example:
                
        >>> import checker
        >>> check = checker.Checker()

    """
    def __init__(self, inputArgv):
    	self.input = inputArgv
        self.inputFile = []
        self.checkInput()
        self.hashTable = {}
        self.getHashTable()
    
    def checkInput(self):
        if not os.path.exists(self.input):
            print "cant find [%s]" % self.input
        else:
            if os.path.isdir(self.input):
                for eachFileName in os.listdir(self.input):
                    eachFile = os.path.join(self.input, eachFileName)
                    if os.path.isfile(eachFile):
                        self.inputFile.append(eachFile)
                    else:
                        print "not file [%s]" % eachFile

    def md5Checksum(self, fileName):
        with open(fileName, "rb") as fileHandle:
            m = hashlib.md5()
            while True:
                data = fileHandle.read(8192)
                if not data:
                   break
                m.update(data)
            return m.hexdigest()

    def getHashTable(self):
        dirList = [eachDir for eachDir in os.listdir("./") if os.path.isdir(eachDir) and eachDir != ".git"]
        for eachDir in dirList:
            for eachFile in os.listdir(eachDir):
                fileName = os.path.join(eachDir, eachFile)
                md5 = self.md5Checksum(fileName)
                if not self.hashTable.has_key(md5):
                    self.hashTable[md5] = fileName

    def addTo(self, inputFile):
        with open(inputFile) as fileHandle:
            content = fileHandle.read()
            if "<?php" in content or "<?" in content:
                ext = "php"
            elif "<%" in content and "%>" in content:
                ext = "asp"
            else:
                ext = "unknown"
            if ext == "unknown":
                print "unknown webshell ext [%s]" % inputFile
            else:
                newFile = os.path.join(ext, os.path.basename(inputFile))
                while os.path.exists(newFile):
                    dirName = os.path.split(newFile)[0]
                    newFileName = os.path.splitext(os.path.split(newFile)[1])[0] + "_1"
                    newFile = os.path.join(dirName, newFileName + ext)
                with open(newFile , "w") as writeHandle:
                    writeHandle.write(content)
                print "add webshell [%s] to [%s]" % (inputFile, ext)

    def processing(self):
        for eachFile in self.inputFile:
            md5 = self.md5Checksum(eachFile)
            if self.hashTable.has_key(md5):
                pass
                #print "this webshell [%s] already exists [%s]" % ( eachFile, self.hashTable[md5] )
            else:
                print "this file is not in this project [%s]" % eachFile
                self.addTo(eachFile)

if __name__ == "__main__":
    check = Checker(sys.argv[1])
    check.processing()
