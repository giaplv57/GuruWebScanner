<?php
$enFil = "includeTestFile";
include $enFil.".php";

/*
Denne test kræver følgende data i databasen:

{
  "test": "includeTest",
  "request": "\/",
  "includes": [
    {
      "current": "\/home\/knox\/sw10\/THAPS\/test\/includeTest.php",
      "line": 3,
      "included": "\/home\/knox\/sw10\/THAPS\/test\/includeTestFile.php"
    }
  ]
}

Stien ovenfor skal sikkert rettes i db'en

Køres med:
php Main.php -r includeTest test/includeTest.php

*/
