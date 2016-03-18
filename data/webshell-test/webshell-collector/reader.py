#!/usr/bin/env python
# -*- coding: UTF-8 -*- 
##############################################################
# Licence: Copyright (c) 2014 pys0lve <shiqiaomu@me.com>
# Date:    2014/11/14 19:00:00
# Brief:   Webshell-Reader
# href:    https://github.com/shiqiaomu/webshell-collector
# V1.0     14 Nov 2014 Initial release
###############################################################

import cPickle
import sys

class Reader(object):
    """
        Some Methods To Read Webshell Response Data
        For example:
                
        >>> import reader
        >>> reader = reader.Reader()

    """
    def __init__(self, fileName):
        self.fileName = fileName
    
    def processing(self):
        with open(self.fileName, "rb") as fileHandle:
            result = cPickle.load(fileHandle)
            print result["webshell"]
            print result["code"]
            print result["headers"]
            print result["content"]

if __name__ == "__main__":
    reader = Reader(sys.argv[1])
    reader.processing()
