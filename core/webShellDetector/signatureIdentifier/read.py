import base64 as b64
with open('shelldetect.db', 'r') as f:
    d = f.read()
d = b64.b64decode(d)
print d
