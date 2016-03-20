import ast
from pprint import pprint

#d = json.loads("{u'scan_id': u'dc91561fd0b7a555e9e1a26fdd189d18832b9d896f50e7f8afa153773d1a851c-1458317030', u'sha1': u'c90b0ba575f432ecc08f8f292f3013b5532fe2c4', u'resource': u'dc91561fd0b7a555e9e1a26fdd189d18832b9d896f50e7f8afa153773d1a851c', u'response_code': 1, u'scan_date': u'2016-03-18 16:03:50', u'permalink': u'https://www.virustotal.com/file/dc91561fd0b7a555e9e1a26fdd189d18832b9d896f50e7f8afa153773d1a851c/analysis/1458317030/', u'verbose_msg': u'Scan finished, information embedded', u'sha256': u'dc91561fd0b7a555e9e1a26fdd189d18832b9d896f50e7f8afa153773d1a851c', u'positives': 21, 'fileName': 'sample (690).shell', u'total': 57, u'md5': u'7b4e81ba8703e7ebeca0001ed18263b3', u'scans': {u'Bkav': {u'detected': False, u'version': u'1.3.0.7744', u'result': None, u'update': u'20160318'}, u'TotalDefense': {u'detected': False, u'version': u'37.1.62.1', u'result': None, u'update': u'20160318'}, u'MicroWorld-eScan': {u'detected': True, u'version': u'12.0.250.0', u'result': u'Backdoor.PHP.Webshell.EI', u'update': u'20160318'}, u'nProtect': {u'detected': True, u'version': u'2016-03-18.01', u'result': u'Backdoor.PHP.Webshell.EI', u'update': u'20160318'}, u'CMC': {u'detected': False, u'version': u'1.1.0.977', u'result': None, u'update': u'20160316'}, u'CAT-QuickHeal': {u'detected': False, u'version': u'14.00', u'result': None, u'update': u'20160318'}, u'McAfee': {u'detected': True, u'version': u'6.0.6.653', u'result': u'PHP/BackDoor.gen', u'update': u'20160318'}, u'Malwarebytes': {u'detected': False, u'version': u'2.1.1.1115', u'result': None, u'update': u'20160318'}, u'VIPRE': {u'detected': False, u'version': u'47968', u'result': None, u'update': u'20160318'}, u'TheHacker': {u'detected': False, u'version': u'6.8.0.5.865', u'result': None, u'update': u'20160315'}, u'BitDefender': {u'detected': True, u'version': u'7.2', u'result': u'Backdoor.PHP.Webshell.EI', u'update': u'20160318'}, u'K7GW': {u'detected': False, u'version': u'9.218.19047', u'result': None, u'update': u'20160318'}, u'K7AntiVirus': {u'detected': False, u'version': u'9.218.19046', u'result': None, u'update': u'20160318'}, u'Baidu': {u'detected': True, u'version': u'1.0.0.2', u'result': u'PHP.Backdoor.WebShell.ac', u'update': u'20160318'}, u'Agnitum': {u'detected': False, u'version': u'5.5.1.3', u'result': None, u'update': u'20160316'}, u'F-Prot': {u'detected': False, u'version': u'4.7.1.166', u'result': None, u'update': u'20160318'}, u'Symantec': {u'detected': False, u'version': u'20151.1.0.32', u'result': None, u'update': u'20160318'}, u'ESET-NOD32': {u'detected': True, u'version': u'13200', u'result': u'PHP/WebShell.NAY', u'update': u'20160318'}, u'TrendMicro-HouseCall': {u'detected': False, u'version': u'9.800.0.1009', u'result': None, u'update': u'20160318'}, u'Avast': {u'detected': True, u'version': u'8.0.1489.320', u'result': u'PHP:Shell-BC [Trj]', u'update': u'20160318'}, u'ClamAV': {u'detected': False, u'version': u'0.98.5.0', u'result': None, u'update': u'20160317'}, u'Kaspersky': {u'detected': False, u'version': u'15.0.1.13', u'result': None, u'update': u'20160318'}, u'Alibaba': {u'detected': False, u'version': u'1.0', u'result': None, u'update': u'20160318'}, u'NANO-Antivirus': {u'detected': False, u'version': u'1.0.18.6677', u'result': None, u'update': u'20160318'}, u'ViRobot': {u'detected': False, u'version': u'2014.3.20.0', u'result': None, u'update': u'20160318'}, u'AegisLab': {u'detected': True, u'version': u'4.2', u'result': u'Backdoor.PHP.WebShell.bq!c', u'update': u'20160318'}, u'Rising': {u'detected': False, u'version': u'25.0.0.18', u'result': None, u'update': u'20160318'}, u'Ad-Aware': {u'detected': True, u'version': u'3.0.2.1015', u'result': u'Backdoor.PHP.Webshell.EI', u'update': u'20160318'}, u'Sophos': {u'detected': False, u'version': u'4.98.0', u'result': None, u'update': u'20160318'}, u'Comodo': {u'detected': True, u'version': u'24587', u'result': u'Backdoor.PHP.WebShell.bq', u'update': u'20160318'}, u'F-Secure': {u'detected': True, u'version': u'11.0.19100.45', u'result': u'Backdoor.PHP.Webshell.EI', u'update': u'20160318'}, u'DrWeb': {u'detected': False, u'version': u'7.0.17.11230', u'result': None, u'update': u'20160318'}, u'Zillya': {u'detected': False, u'version': u'2.0.0.2732', u'result': None, u'update': u'20160317'}, u'TrendMicro': {u'detected': False, u'version': u'9.740.0.1012', u'result': None, u'update': u'20160318'}, u'McAfee-GW-Edition': {u'detected': True, u'version': u'v2015', u'result': u'PHP/BackDoor.gen', u'update': u'20160318'}, u'Emsisoft': {u'detected': True, u'version': u'3.5.0.656', u'result': u'Backdoor.PHP.Webshell.EI (B)', u'update': u'20160318'}, u'Cyren': {u'detected': False, u'version': u'5.4.16.7', u'result': None, u'update': u'20160318'}, u'Jiangmin': {u'detected': False, u'version': u'16.0.100', u'result': None, u'update': u'20160318'}, u'Avira': {u'detected': True, u'version': u'8.3.3.2', u'result': u'PHP/Shell.BC.2', u'update': u'20160318'}, u'Fortinet': {u'detected': False, u'version': u'5.1.220.0', u'result': None, u'update': u'20160318'}, u'Antiy-AVL': {u'detected': False, u'version': u'1.0.0.1', u'result': None, u'update': u'20160318'}, u'Arcabit': {u'detected': True, u'version': u'1.0.0.662', u'result': u'Backdoor.PHP.Webshell.EI', u'update': u'20160318'}, u'SUPERAntiSpyware': {u'detected': False, u'version': u'5.6.0.1032', u'result': None, u'update': u'20160318'}, u'AhnLab-V3': {u'detected': True, u'version': u'2016.03.19.00', u'result': u'PHP/Webshell', u'update': u'20160318'}, u'Microsoft': {u'detected': False, u'version': u'1.1.12505.0', u'result': None, u'update': u'20160318'}, u'ByteHero': {u'detected': False, u'version': u'1.0.0.2', u'result': None, u'update': u'20160318'}, u'ALYac': {u'detected': True, u'version': u'1.0.1.9', u'result': u'Backdoor.PHP.Webshell.EI', u'update': u'20160318'}, u'AVware': {u'detected': False, u'version': u'1.5.0.42', u'result': None, u'update': u'20160318'}, u'VBA32': {u'detected': False, u'version': u'3.12.26.4', u'result': None, u'update': u'20160318'}, u'Panda': {u'detected': False, u'version': u'4.6.4.2', u'result': None, u'update': u'20160318'}, u'Zoner': {u'detected': False, u'version': u'1.0', u'result': None, u'update': u'20160318'}, u'Tencent': {u'detected': True, u'version': u'1.0.0.1', u'result': u'Php.Backdoor.Webshell.Aiio', u'update': u'20160318'}, u'Ikarus': {u'detected': True, u'version': u'T3.2.0.9.0', u'result': u'Trojan.PHP.WebShell', u'update': u'20160318'}, u'GData': {u'detected': True, u'version': u'25', u'result': u'Backdoor.PHP.Webshell.EI', u'update': u'20160318'}, u'AVG': {u'detected': False, u'version': u'16.0.0.4542', u'result': None, u'update': u'20160318'}, u'Baidu-International': {u'detected': False, u'version': u'3.5.1.41473', u'result': None, u'update': u'20160318'}, u'Qihoo-360': {u'detected': True, u'version': u'1.0.0.1120', u'result': u'Malware.Radar01.Gen', u'update': u'20160318'}}}")

#s = '{"favorited": false, "contributors": null}'

count = {
'Bkav': 0,
'TotalDefense': 0,
'MicroWorld-eScan': 0,
'nProtect': 0,
'CMC': 0,
'CAT-QuickHeal': 0,
'ALYac': 0,
'Malwarebytes': 0,
'Zillya': 0,
'AegisLab': 0,
'TheHacker': 0,
'BitDefender': 0,
'K7GW': 0,
'K7AntiVirus': 0,
'Baidu': 0,
'NANO-Antivirus': 0,
'F-Prot': 0,
'Symantec': 0,
'ESET-NOD32': 0,
'TrendMicro-HouseCall': 0,
'Avast': 0,
'ClamAV': 0,
'GData': 0,
'Kaspersky': 0,
'Alibaba': 0,
'Agnitum': 0,
'SUPERAntiSpyware': 0,
'Tencent': 0,
'Ad-Aware': 0,
'Emsisoft': 0,
'Comodo': 0,
'F-Secure': 0,
'DrWeb': 0,
'VIPRE': 0,
'TrendMicro': 0,
'McAfee-GW-Edition': 0,
'Sophos': 0,
'Cyren': 0,
'Jiangmin': 0,
'Avira': 0,
'Antiy-AVL': 0,
'Arcabit': 0,
'ViRobot': 0,
'AhnLab-V3': 0,
'Microsoft': 0,
'ByteHero': 0,
'McAfee': 0,
'AVware': 0,
'VBA32': 0,
'Panda': 0,
'Zoner': 0,
'Rising': 0,
'Ikarus': 0,
'Fortinet': 0,
'AVG': 0,
'Baidu-International': 0,
'Qihoo-360': 0
}

avs = ['Bkav', 'TotalDefense', 'MicroWorld-eScan', 'nProtect', 'CMC', 'CAT-QuickHeal', 'ALYac', 'Malwarebytes', 'Zillya', 'AegisLab', 'TheHacker', 'BitDefender', 'K7GW', 'K7AntiVirus', 'Baidu', 'NANO-Antivirus', 'F-Prot', 'Symantec', 'ESET-NOD32', 'TrendMicro-HouseCall', 'Avast', 'ClamAV', 'GData', 'Kaspersky', 'Alibaba', 'Agnitum', 'SUPERAntiSpyware', 'Tencent', 'Ad-Aware', 'Emsisoft', 'Comodo', 'F-Secure', 'DrWeb', 'VIPRE', 'TrendMicro', 'McAfee-GW-Edition', 'Sophos', 'Cyren', 'Jiangmin', 'Avira', 'Antiy-AVL', 'Arcabit', 'ViRobot', 'AhnLab-V3', 'Microsoft', 'ByteHero', 'McAfee', 'AVware', 'VBA32', 'Panda', 'Zoner', 'Rising', 'Ikarus', 'Fortinet', 'AVG', 'Baidu-International', 'Qihoo-360']

def check(scand, av):
    try:
        if scand[av]['detected']:
            count[av] += 1
    except Exception, e:
        return 0


with open("scanResult.json", "r") as f:
    lines = f.readlines()
    for line in lines:
        e = ast.literal_eval(line)
        scand = e['scans']
        for av in avs:
            check(scand, av) 
    print count

#pprint(d)
