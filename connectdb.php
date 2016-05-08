<?php
 
    
    function ConnectDB(){
        $dbfile = file_get_contents("dbconfig/db.cfg");
        $dbinfo = json_decode($dbfile, true);
        $server     = $dbinfo['server'];
        $username   = $dbinfo['username'];
        $password   = $dbinfo['password'];
        $dbname     = $dbinfo['name'];
        $con    = mysqli_connect($server, $username, $password, $dbname);        
        return $con;
    }
    ConnectDB();
?>
