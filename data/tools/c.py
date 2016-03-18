import requests
import re
import os


for i in range (1, 3):
    url = "https://github.com/search?utf8=%E2%9C%93&q=plugin+wordpress+language%3APHP&type=Repositories&ref=advsearch&l=PHP&l=&p={0}".format(i)
    req = requests.get(url)
    searchResult = req.text
    searchResultWithoutEndline = searchResult.replace("\n", "")
    # print searchResultWithoutEndline
    matchList = re.findall(r"<h3 class=\"repo-list-name\">    <a href=\"(.*?)</a>      </h3>", searchResultWithoutEndline, flags=0)
    if matchList:
        for project in matchList:
           projectDownloadURL = "https://github.com/" + re.sub(r"\">.*", "", project) + "/archive/master.zip"
           os.system("wget " + projectDownloadURL)
    else:
        print "Not found in page" + str(i)
        continue

