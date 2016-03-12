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
            @mysqli_close($con) or die("Cannot close sql connect!");

            if ($FileLocation!==null and file_exists($FileLocation)) {
                header('Content-Description: File Transfer');
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename='.basename($FileLocation));
                header('Content-Transfer-Encoding: binary');
                header('Expires: 0');
                header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
                header('Pragma: public');
                header('Content-Length: ' . filesize($FileLocation));
                ob_clean();
                flush();
                readfile($FileLocation);
                exit;
            }else{
                header("Location: index.php");
                die();
            }
        }elseif ($role === '1'){
            $query1 = mysqli_query($con, "SELECT location FROM `files` where fid = '$FileId'");
            $FileLocation = mysqli_fetch_array($query1)['location'];
            @mysqli_close($con) or die("Cannot close sql connect!");

            if ($FileLocation!==null and file_exists($FileLocation)) {
                header('Content-Description: File Transfer');
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename='.basename($FileLocation));
                header('Content-Transfer-Encoding: binary');
                header('Expires: 0');
                header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
                header('Pragma: public');
                header('Content-Length: ' . filesize($FileLocation));
                ob_clean();
                flush();
                readfile($FileLocation);
                exit;
            }else{
                header("Location: index.php");
                die();
            }
        }else{
            header("Location: index.php");
            die();
        }
    }else{
        header("Location: index.php");
        die();
    }
?>
