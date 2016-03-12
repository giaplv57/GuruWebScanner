
<?php 

  if (isset($_POST["submit"])) {
    if (is_array($_FILES["userFile"]["name"])) die();
    $projectName     = htmlspecialchars($_FILES["userFile"]["name"]);  
    $compressType = pathinfo($projectName, PATHINFO_EXTENSION);               
    $projectCheckSum = sha1_file($_FILES["userFile"]["tmp_name"]);
    $projectID  = sha1($projectCheckSum.round(microtime(true) * 1000));
    $targetProject  = "./userProjects/" . $projectID . "." . $compressType;
    $uploadOk     = 1;

    // Check if file already exists
    if (file_exists($targetProject)) {
      echo '<div class="alert alert-warning col-md-4" role="alert">Error! File already exists.</div>';
      $uploadOk = 0;
    }
    // Check file size
    if ($_FILES["userFile"]["size"] > 104857600) { //100MB limited
      echo '<div class="alert alert-warning col-md-4" role="alert">Error! Your file is too large.</div>';
      $uploadOk = 0;
    }
    // Allow certain file formats
    if ($compressType != "tar" && $compressType != "zip" && $compressType != "rar" && $compressType != "7z" && $compressType != "php") {
      echo '<div class="alert alert-warning col-md-4" role="alert">Error! Only tar, zip, 7z, rar or php file is allowed.</div>';
      $uploadOk = 0;
    }
    // Check if $uploadOk is set to 0 by an error
    if (!($uploadOk == 0 || !move_uploaded_file($_FILES["userFile"]["tmp_name"], $targetProject))){
      mkdir("userProjects/" . $projectID, 0777); //can't create contain folder and extract tar file in 1 command
      $uncompressFolder = "./userProjects/".$projectID."/";
      if($compressType == "tar"){   
        exec("tar -xf ".$targetProject." -C ".$uncompressFolder);
      }else if($compressType == "zip"){
        exec("unzip ".$targetProject." -d ".$uncompressFolder);
      }else if($compressType == "rar"){
        exec("unrar x ".$targetProject." ".$uncompressFolder);
      }else if($compressType == "7z"){
        exec("7z x ".$targetProject." -o".$uncompressFolder);
      }else if($compressType == "php"){
        $safefilename = str_replace(" ", "\ ", $filename);  
        exec("mkdir ".$uncompressFolder."; cp ".$targetProject." ".$uncompressFolder."/".$safefilename);        
      }else{
        // die();
      }
      // setcookie("checksum", $fileCheckSum, time() + (86400), "/"); #ONE DAY COOKIE
      setcookie("projectID", $projectID, time() + (86400/2), "/"); #HALF DAY COOKIE
      setcookie("projectName", $projectName, time() + (86400/2), "/"); #HALF DAY COOKIE
      echo $uploadOk;
    }
  }
?>