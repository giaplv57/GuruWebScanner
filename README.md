![](./assets/img/logo.png?raw=true)

An On-The-Cloud free "greybox" box scanner for various purposes.

Scan Vulnerability • Detect WebShell/Backdoor

## Key Features
* Detect following the vulnebilities: XSS, SQLInjection, File Inclusion...
* Detect WebShell/Backdoor

## Requirements:
`php 5.6.12` , `mysql`, `Apache/2.4.16`, `unzip`, `unrar`, `7z`, `python-mysqldb`, `yara`, `python-yara`

## Usage:
* Install [requirements](https://www.digitalocean.com/community/tutorials/how-to-install-linux-apache-mysql-php-lamp-stack-on-ubuntu)
* Create a database named `guruWS` and import `import-me-first.sql`
```
$ mysql -uUSERNAME -pPASSWORD
(mysql) CREATE database guruWS
(mysql) exit
$ mysql -uUSERNAME -pPASSWORD DATABASE < dbconfig/import-me-first.sql
```
* Change user and password of mysql in `config/db.cfg` file
* chmod upload directory
```
chmod 777 -R userProjects/
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
restart the `httpd` service

## Screenshot
![home page](./assets/img/home.JPG?raw=true)

-+-

![result page](./assets/img/result.JPG?raw=true)

-+-

![result page](./assets/img/result-shell.JPG?raw=true)

## Changelog
* Not yet released

## Thanks to
* https://github.com/nbs-system/php-malware-finder
* https://github.com/emposha/Shell-Detector
* https://github.com/robocoder/rips-scanner
* https://github.com/Neohapsis/NeoPI
* Web Shell repositories: https://github.com/tennc/webshell, https://github.com/shiqiaomu/webshell-collector, https://github.com/tdifg/WebShell, https://github.com/BlackArch/webshells, https://github.com/JohnTroony/other-webshells,
https://github.com/lhlsec/webshell, https://github.com/fuzzdb-project/fuzzdb, https://github.com/JohnTroony/php-webshells
