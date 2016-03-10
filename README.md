![](https://raw.githubusercontent.com/giaplv57/GuruWebScanner/master/assets/img/logo.png?token=AE0vQtc2OvfRVApR59212yiw4tPApLBtks5W54jxwA%3D%3D)

An On-The-Cloud free "greybox" box scanner for various purposes.

## Key Features
* Detect following the vulnebilities: XSS, SQLInjection, File Inclusion...
* Detect WebShell

## Requirements:
`php 5.6.12` , `mysql`, `Apache/2.4.16`, `unzip`, `unrar`, `7z`, `python-mysqldb`, `yara`, `python-yara`

## Usage:
* Install [requirements](https://www.digitalocean.com/community/tutorials/how-to-install-linux-apache-mysql-php-lamp-stack-on-ubuntu)
* Create a database named guruWS and import guruWS.sql
```
$ mysql -uUSERNAME -pPASSWORD
(mysql) CREATE database guruWS
(mysql) exit
$ mysql -uUSERNAME -pPASSWORD DATABASE < database/guruWS.sql
```
* Change user and password of mysql in `connectdb.php` and `core/grVulnScanner/jobAllocate.py` files
* chmod upload directory
```
chmod 777 -R userFiles/
```
* Run `jobAllocate.py` as a service
```
sudo python jobAllocate.py &
```
* Increase the max file size for upload file as well as max size of post request in php.ini (optional)
```
------- /etc/php5/apache2/php.ini ------
upload_max_filesize = 200M
post_max_size = 800M
```

## Screenshot
![home page](https://raw.githubusercontent.com/giaplv57/GuruWebScanner/master/assets/img/home.JPG?token=AE0vQonRB5ES6wzWbgg3qCO7zMsHWgc6ks5W54lLwA%3D%3D)

-+-

![result page](https://raw.githubusercontent.com/giaplv57/GuruWebScanner/master/assets/img/result.JPG?token=AE0vQiTk7nwSGXAObfl5ApJZvlBucPZxks5W54lUwA%3D%3D)

-+-

![result page](https://raw.githubusercontent.com/giaplv57/GuruWebScanner/master/assets/img/result-shell.JPG?token=AE0vQjkzbmkw32oQMPzXbCoDv0_SZ0I9ks5W6iQZwA%3D%3D)

## Changelog
* Not yet released
