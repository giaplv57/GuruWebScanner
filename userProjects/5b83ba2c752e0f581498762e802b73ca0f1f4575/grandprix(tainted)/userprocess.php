<?php
    include ('naviBar.php');
    if(isset($_SESSION['username']) and $_SESSION['role']==='1' and isset($_GET['action']) and isset($_GET['uid'])){
    	$UserId = $_GET['uid'];
    	$con = ConnectDB();
    	if ($_GET['action']==='block'){
    		mysqli_query($con,"UPDATE users SET status='0' where id='$UserId'");
    	}
    	if ($_GET['action']==='active'){
    		mysqli_query($con,"UPDATE users SET status='1' where id='$UserId'");
    	}
        if ($_GET['action']==='toadmin'){
            mysqli_query($con,"UPDATE users SET role='1' where id='$UserId'");
        }
        if ($_GET['action']==='tomember'){
            mysqli_query($con,"UPDATE users SET role='0' where id='$UserId'");
        }
    	@mysqli_close($con) or die("Cannot close sql connect!");
    	header("Location: usermanager.php");
		die();
    }else{
    	header("Location: index.php");
		die();
    }
?>