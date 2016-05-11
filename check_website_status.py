import requests
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
import datetime
import time
import json
import MySQLdb

MINTIME = 6000

try:
    DBCONFIGFILE = "dbconfig/db.cfg"   
    with open(DBCONFIGFILE) as configfile:    
        dbconf = json.load(configfile)
    DBserver = dbconf['server']
    DBusername = dbconf['username']
    DBpassword = dbconf['password']
    DBname = dbconf['name']    
except Exception, e:    
    raise Exception, e

def notify(web, status):    
    name = web['name'].strip()
    toemail = web['email'].strip()
    url = web['url'].strip().split('//')[1]
    lang = web['lang'].strip()
    datatime = datetime.datetime.now().strftime("%A, %d. %B %Y %I:%M%p")
    if lang != 'vi':
        return False    
    if status == 'down':
        message = "Chao " + name + ",\r\nGuruWS xin thong bao:\nTrang web " + url + " hien khong the truy cap duoc hoac truy cap qua cham vao thoi diem " + datatime + "\r\n"
    else:
        message = "Chao " + name + ",\r\nGuruWS xin thong bao:\nTrang web " + url + " hien da co the truy cap duoc vao thoi diem " + datatime + "\r\n"    

    #try:
        # message += "Chi tiet:\r\nGET " + url + " (" + str(r.status_code) + ")" + "\r\n" + str(r.headers)
    #except Exception, e:        
    #    pass

    message += "\r\n\r\n\r\n--\r\nBan nhan duoc thu nay vi da dang ky cap nhat trang thai Website tai guruws.tech.\r\nCam on ban da su dung dich vu\r\nNeu can ho tro gi them (vi du nhu khac phuc su co, tim kiem ho hong website) cac ban co the lien he voi chung toi qua email nay hoac duong day nong: 01646543714\r\nGuruTeam"
 
    try:
        fromaddr = "guruws.tech@gmail.com"
        msg = MIMEMultipart()
        msg['From'] = "Guru Team"
        msg['To'] = toemail

        if status == 'down':
            msg['Subject'] = "GuruWS: " + url + " khong truy cap duoc hoac truy cap qua cham"
        else:
            msg['Subject'] = "GuruWS: " + url + " da co the truy cap duoc"

        body = message
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login("guruws.tech@gmail.com", "where.are.you.now?")
         
        text = msg.as_string()
        #server.sendmail(fromaddr, toemail, text)
        server.quit()
    except Exception, e:
        print "[+] Gui mail loi: " + str(e)
        pass

    print "Sent notification to " + web['email']


def get_urllist():

    # Have to make new connection in every while loop because
    # of the connection time limitation of DBMS
    try:
        conn = MySQLdb.connect(DBserver, DBusername, DBpassword, DBname)
        cursor = conn.cursor()

        # execute SQL query using execute() method.
        cursor.execute("SELECT * FROM webChecker")

        # Fetch a single row using fetchone() method.
        rows = cursor.fetchall()
        
        cursor.close()
        conn.close()
    except Exception, e:
        print e
        raise Exception, e

    weblist = []
    for row in rows:
        web = {
            'id': row[0],
            'url': row[1],
            'email': row[2],
            'name': row[3],
            'lang': row[4],
            'status': row[5],
            'time': row[6]
        }
        if web['time'] == None or web['time'] < MINTIME:
            web['time'] = MINTIME
        
        weblist.append(web)
    return weblist


def update_status(web, status):
    try:
        conn = MySQLdb.connect(DBserver, DBusername, DBpassword, DBname)
        cursor = conn.cursor()
        cursor.execute('UPDATE webChecker SET ustatus = \"' + status + '\" WHERE uwebsite = \"' + web['url'] + '\" and uemail = \"' + web['email'] + '\" ' )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception, e:
        print e
        raise Exception, e
    return True    


def update_time(web, round_trip):
    if round_trip < MINTIME:
        round_trip = MINTIME
    try:
        conn = MySQLdb.connect(DBserver, DBusername, DBpassword, DBname)
        cursor = conn.cursor()
        cursor.execute('UPDATE webChecker SET utime = ' + str(round_trip) + ' WHERE id = ' + str(web['id']))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception, e:
        print e
        raise Exception, e
    return True    


def check_website_status():    
    weblist = get_urllist()
    
    for web in weblist:                
        if not '@' in web['email']:
            continue
        up = True

        start = time.time()
        try:       
            timelimit =  web['time'] * 2 / 1000
            # print "timelimit ", timelimit
            r = requests.get(web['url'], verify=False, timeout=timelimit)            
            round_trip = int((time.time() - start) // 0.001)
            if r.status_code != 200:
                up = False
        except Exception, e:
            #print "[+] Error ! " + str(e)
            up = False            
            pass

        if up:
            print '[+] ' + web['url'] + "\t: Up (" + str(round_trip) + " ms)"
            update_time(web, round_trip)
            if web['status'] == 'down':
                notify(web, 'up')
                update_status(web, 'up')
        else:
            print '[+] ' + web['url'] + "\t: Down"
            if web['status'] == 'up':                                      
                notify(web, 'down')
                update_status(web, 'down')

def try_connect():
    try:
        conn = MySQLdb.connect(DBserver, DBusername, DBpassword, DBname)
    except:
        return False

    return True;

def welcome():
    if try_connect():
        print green("[+] Connected to database !\n\n")
    else:
        print red("[+] Can't connect to database !")
        exit(0)

if __name__ == '__main__':    
    cnt = 0
    while True:
        dt = datetime.datetime.now().strftime("%A, %d. %B %Y %I:%M%p")
        print "[+] ", dt
        cnt += 1
        check_website_status()
        time.sleep(2)
