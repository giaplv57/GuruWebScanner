import requests
import re
import os
import hashlib

for i in range (1, 3):
    url = "https://github.com/search?utf8=%E2%9C%93&q=plugin+wordpress+language%3APHP&type=Repositories&ref=advsearch&l=PHP&l=&p={0}".format(i)
    req = requests.get(url)
    searchResult = req.text
    searchResultWithoutEndline = searchResult.replace("\n", "")
    # print searchResultWithoutEndline
    matchList = re.findall(r' <a class="muted-link" href="(.*?)">', searchResultWithoutEndline, flags=0)
    if matchList:
        for project in matchList:
            filename = re.sub(r"\">.*", "", project)[:-10]
            if filename[-1] == '/':
                filename = filename[:-1]
            projectDownloadURL = "https://github.com/" + filename + "/archive/master.zip"
            print projectDownloadURL
            os.system("wget " + projectDownloadURL + " -O " + hashlib.md5(filename).hexdigest() + ".zip")
    else:
        print "Not found in page" + str(i)
        continue

