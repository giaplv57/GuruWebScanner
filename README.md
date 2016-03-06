![](https://raw.githubusercontent.com/giaplv57/GuruWebScanner/master/img/logo.png?token=AE0vQt_IIAU2FXj9-WfYHMNRVOyRGND6ks5W4TZPwA%3D%3D)

An On-The-Cloud free "greybox" box scanner for various purposes.

## Key Features
* Detect following the vulnebilities: XSS, SQLInjection, File Inclusion...
* Detect WebShell

## Requirements:
`php 5.6.12` , `mysql`, `Apache/2.4.16`, `unzip`, `unrar`, `7z`, `python-mysqldb`

## Usage:
* Install [requirements](https://www.digitalocean.com/community/tutorials/how-to-install-linux-apache-mysql-php-lamp-stack-on-ubuntu)
* Create a database named guruWS and import guruWS.sql
```
$ mysql -uUSERNAME -pPASSWORD
(mysql) CREATE database guruWS
(mysql) exit
$ mysql -uUSERNAME -pPASSWORD DATABASE < database/guruWS.sql
```
* Change user and password of mysql in `connectdb.php` and `scanner/jobAllocate.py` files
* chmod upload directory
```
chmod 777 -R userFiles/
```
* Run jobAllocate.py in `scanner/` as a service
```
python jobAllocate.py &
```
* Increase the max file size for upload file as well as max size of post request in php.ini (optional)
```
------- /etc/php5/apache2/php.ini ------
upload_max_filesize = 200M
post_max_size = 800M
```

## Screenshot
![home page](https://raw.githubusercontent.com/giaplv57/GuruWebScanner/master/img/home.JPG?token=AE0vQj9zpTozY8zQnFEi5gpXc7aCQxEsks5W4TenwA%3D%3D)

![result page](https://raw.githubusercontent.com/giaplv57/GuruWebScanner/master/img/result.JPG?token=AE0vQmmugAqIS9khd_6NG9RpAVbuJBAVks5W4TetwA%3D%3D)

## Changelog
* Not yet released
