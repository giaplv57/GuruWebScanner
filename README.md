# GuruWebScanner
An On-The-Cloud free "greybox" box scanner for various purposes.

## Key Features
* Detect following the vulnebilities: XSS, SQLInjection, File Inclusion...
* Detect WebShell

## Requirements:
`php 5.6.12` , `mysql`, `Apache/2.4.16`, `unzip`, `unrar`, `python-mysqldb`

## Usage:
* Install [requirements](https://www.digitalocean.com/community/tutorials/how-to-install-linux-apache-mysql-php-lamp-stack-on-ubuntu)
* Create a database named guruWS and import guruWS.sql
```
$ mysql -uUSERNAME -pPASSWORD
(mysql) CREATE database guruWS
(mysql) exit
$ mysql -uUSERNAME -pPASSWORD DATABASE < database/guruWS.sql
```
* Change user and password of mysql in connectdb.php and scanner/jobAllocate.py files
* chmod upload directory
```
chmod 777 -R userFiles/
```
* Run jobAllocate.py as a service
```
python jobAllocate.py &
```
* Increase the max file size for upload file as well as max size of post request in php.ini (optional)
```
------- /etc/php5/apache2/php.ini ------
upload_max_filesize = 200M

```

## Screenshot
![home page](https://raw.githubusercontent.com/giaplv57/GuruWebScanner/master/img/screenshot/home.jpg?token=AE0vQvA4-EiGkFjOlf7yfDHnRkFcBM8jks5WAck6wA%3D%3D)

![result page](https://raw.githubusercontent.com/giaplv57/GuruWebScanner/master/img/screenshot/result.JPG?token=AE0vQjgCbOwsGx3sy-U9fpTH-BYYq7yQks5WAcliwA%3D%3D)

## Changelog
* Not yet released
