<?php
    include ('naviBar.php');
    if(isset($_SESSION['username']) and isset($_SESSION['role'])){
        $role = $_SESSION['role'];
        $con = ConnectDB();
        $FileId = $_GET['FileId'];
        if ($role === '0'){
            $query1 = mysqli_query($con, "SELECT id FROM `users` where username = '$username'");
            $row = mysqli_fetch_array($query1);
            $UserId = $row['id'];
            $query2 = mysqli_query($con, "SELECT location FROM `files` where uid = '$UserId' and fid = '$FileId'");
            $FileLocation = mysqli_fetch_array($query2)['location'];
            if ($FileLocation!==null and file_exists($FileLocation)) {
                unlink($FileLocation);
                $query3 = mysqli_query($con, "DELETE FROM files WHERE fid=$FileId and uid=$UserId");
                header("Location: myfiles.php");
                die();
            }else{
                header("Location: index.php");
                die();
            }
        }else{
            $query1 = mysqli_query($con, "SELECT location FROM `files` where fid = '$FileId'");
            $FileLocation = mysqli_fetch_array($query1)['location'];
            if ($FileLocation!==null and file_exists($FileLocation)) {
                unlink($FileLocation);
                $query2 = mysqli_query($con, "DELETE FROM files WHERE fid=$FileId");
                header("Location: filemanager.php");
                die();
            }else{
                header("Location: index.php");
                die();
            }
        }
    }else{
        header("Location: index.php");
        die();
    }
    @mysqli_close($con) or die("Cannot close sql connect!");
?>
