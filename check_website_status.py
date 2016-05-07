import requests
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
import datetime
import time

def notify(toemail, url, r):
    datatime = datetime.datetime.now().strftime("%A, %d. %B %Y %I:%M%p")
    message = "GuruWS xin thong bao:\nTrang web " + url + " hien khong the truy cap duoc vao thoi diem " + datatime + "\r\n"
    message += "More information:\r\nGET " + url + " (" + str(r.status_code) + ")" + "\r\n" + str(r.headers)

    print message
 
    try:
        fromaddr = "guruws.tech@gmail.com"
        msg = MIMEMultipart()
        msg['From'] = "Guru Team"
        msg['To'] = toemail
        msg['Subject'] = "GuruWS: " + url + " khong truy cap duoc"

        body = message
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login("guruws.tech@gmail.com", "where.are.you.now?")
         
        text = msg.as_string()
        server.sendmail(fromaddr, toemail, text)
        server.quit()
    except Exception, e:
        print "[+] Gui mail loi: " . str(e)


def check_website_status():    
    urllist = ['http://guruws.tech']
    for url in urllist:
        try:        
            r = requests.get(url)
        except Exception, e:
            print "[+] Error ! " + str(e)
            continue
        if r.status_code != 200:
            print '[+] ' + url + " : OK"
        else:
            save_status_code = r.status_code

            # recheck
            r = requests.get(url)
            if r.status_code == save_status_code:
                email = 'htung.nht@gmail.com'
                #email = 'giaplvk57@gmail.com'                        
                notify(email, url, r)

if __name__ == '__main__':
    cnt = 0
    while True:
        print "[+] ", cnt
        cnt += 1
        check_website_status()
        time.sleep(2)
