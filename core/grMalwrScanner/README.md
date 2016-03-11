![](https://raw.githubusercontent.com/giaplv57/GuruWebScanner/master/assets/img/logo.png?token=AE0vQtc2OvfRVApR59212yiw4tPApLBtks5W54jxwA%3D%3D)

# grMalwrScanner
a small part of Guru Project

## Key Features
* Detect WebShell and dangerous functions

## Requirements:
`yara`, `python-yara`

## Usage:
```
$ python main.py                                 20:00:25
Usage: main.py [options]

Options:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory=DIRECTORY
                        specify directory to scan
  -f FILENAME, --filename=FILENAME
                        specify file to scan
  -o OUTFILE, --outfile=OUTFILE
                        specify outfile to write result using JSON
  -p PATTERNDB, --patterndb=PATTERNDB
                        specify patterndb file
  -q, --quite           enable quite mode

$ python main.py -d ../../userFiles/5fd8f263781c4b6dbfb6f14878be34bc3fb7c0df/
[+] Scanning...	 /5fd8f263781c4b6dbfb6f14878be34bc3fb7c0df//shell.php
[+] Found...	 SHELL_SHELLDETECT_spam_2__0__php 	in (/5fd8f263781c4b6dbfb6f14878be34bc3fb7c0df//shell.php)
[+] Analized	: 1 files 
[+] Found	: 1 shells 

```

## Changelog
* Not yet released

