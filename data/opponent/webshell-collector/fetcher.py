#!/usr/bin/env python
# -*- coding: UTF-8 -*- 
##############################################################
# Licence: Copyright (c) 2014 pys0lve <shiqiaomu@me.com>
# Date:    2014/11/14 19:00:00
# Brief:   Webshell-Response-Fetcher
# href:    https://github.com/shiqiaomu/webshell-collector
# V1.0     14 Nov 2014 Initial release
###############################################################

import os
import sys
import threading
import Queue
import time
import urllib2
import urlparse
import cPickle

class Worker(threading.Thread):
    """
        Some Methods To Start MutilThread
        For example:
                
        >>> import fetcher
        >>> worker = fetcher.Worker()

    """
    def __init__(self, workQueue):
        """
            Initial Function

            @type  workQueue: Queue Object
            @param workQueue: Queue

        """
        super(Worker, self).__init__()
        self.workQueue = workQueue
        self.start()

    def run(self):
        """
            Inherited From The Parent Class Threading

        """
        while True:
            if not self.workQueue.empty():
                callFunc, args = self.workQueue.get()
                res = callFunc(*args)
                #print threading.current_thread(), [callFunc], [arg for arg in args]
            else: break

class Manager(object):
    """
        Some Methods To Manage Workers
        For example:
                
        >>> import fetcher
        >>> manager = fetcher.Manager()

    """
    def __init__(self, workerNum = 10):
        """
            Initial Function

            @type  workerNum: Int
            @param workerNum: Num Of Workers By Default Is 10

        """
        self.workQueue = Queue.Queue(1000)
        self.workers = []
        self.workerNum = workerNum
        self.callWorker()

    def callWorker(self):
        """
            Call Worker Function
            Initial MutilWorkers

        """
        for x in xrange(int(self.workerNum)):
            worker = Worker(self.workQueue)
            self.workers.append(worker)

    def addWork(self, callFunc, *args):
        """
            Add Works To Queue Function

            @type  callFunc: Function
            @param callFunc: Work To Be Done
            @type  *args: Any Type
            @param *args: callFunc's Parameter

        """
        self.workQueue.put( (callFunc, args) )


class Fetcher(object):
    """
        Some Methods To Manage Workers
        For example:
                
        >>> import fetcher
        >>> fetcher = fetcher.Fetcher()

    """
    def __init__(self, urlPrefix):
        """
            Initial Function

        """
        self.urlPrefix = urlPrefix
        self.files = []
        self.getFiles()
        self.manager = Manager(30)
        self.SaveDir = "./result/"
        if not os.path.exists(self.SaveDir):
            os.mkdir(self.SaveDir)

    def getFiles(self):
        """
            Get Files

        """
        for eachFile in os.listdir("./php"):
            self.files.append(eachFile)
            
    def fetch(self, fileName):
        """
            Fetch Webshell's Reponse Data

            @type  fileName: String
            @param fileName: Webshell Name

        """
        result = {"webshell": fileName}
        url = urlparse.urljoin(self.urlPrefix, fileName)
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36"}

        try:
            request = urllib2.Request(url, headers = headers)
            response = urllib2.urlopen(request)
            result["code"] = response.getcode()  # response.code
            result["headers"] = response.info()  # response.headers
            result["content"] = response.read() 
        except urllib2.HTTPError, exception:
            result["code"] = exception.code
            result["headers"] = exception.headers
            result["content"] = exception.read()
        except urllib2.URLError, exception:
            print exception.reason

        with open(os.path.join(self.SaveDir, fileName + ".data"), "wb") as fileHandle:
            cPickle.dump(result, fileHandle)

    def processing(self):
        """
            Main Function

        """
        for eachFile in self.files:
            self.manager.addWork(self.fetch, eachFile)

if __name__ == "__main__":
    fetcher = Fetcher(sys.argv[1])
    fetcher.processing()
