def tohex(s):
        return " ".join("{:02x}".format(ord(c)) for c in s)

with open('output.txt', 'rb') as f:
    lines = f.readlines()

f = open('shelldetect.yara', 'w')
for line in lines:
    b = line.split('\"')
    try:
        sign = b[1]
        shellname = b[3]
        if shellname == 'version':
            continue
        print shellname, sign
    except:
        continue

    shellname = shellname.split('/')[-1]
    shellname = shellname.replace('.', '_')
    shellname = shellname.replace('-', '_')
    shellname = shellname.replace('+', '_')
    shellname = shellname.replace(' ', '_')
    shellname = shellname.replace('(', '_')
    shellname = shellname.replace(')', '_')
    shellname = shellname.replace(']', '')
    shellname = shellname.replace('[', '_')
    shellname = shellname.replace('#', '_')
    shellname = shellname.replace('=', '_')
    shellname = shellname.replace('{', '_')
    shellname = shellname.replace('}', '_')
    shellname = shellname.replace('\'', '_')
    shellname = shellname.replace('%', '_')

    f.write('rule ' + 'SHELLDETECT_' + shellname + '\n{\n\tstrings:\n')
    f.write('\t\t$ = {'  + tohex(sign) + '}\n')
    f.write('\tcondition:\n')
    f.write('\t\tany of them\n')
    f.write('}\n\n')


f.close()
