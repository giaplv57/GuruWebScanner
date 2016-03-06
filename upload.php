
<?php 
  if (isset($_POST["submit"])) {
    if (is_array($_FILES["userFile"]["name"])) die();
    $filename     = htmlspecialchars($_FILES["userFile"]["name"]);  
    $compressType = pathinfo($filename, PATHINFO_EXTENSION);               
    $fileCheckSum = sha1_file($_FILES["userFile"]["tmp_name"]);
    $newFilename  = sha1($fileCheckSum.round(microtime(true) * 1000));
    $target_file  = "./userFiles/" . $newFilename . "." . $compressType;
    $uploadOk     = 1;

    // Check if file already exists
    if (file_exists($target_file)) {
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
    if (!($uploadOk == 0 || !move_uploaded_file($_FILES["userFile"]["tmp_name"], $target_file))){
      mkdir("userFiles/" . $newFilename, 0777); //can't create contain folder and extract tar file in 1 command
      $uncompressFolder = "./userFiles/".$newFilename."/";
      if($compressType == "tar"){   
        exec("tar -xf ".$target_file." -C ".$uncompressFolder);
      }else if($compressType == "zip"){
        exec("unzip ".$target_file." -d ".$uncompressFolder);
      }else if($compressType == "rar"){
        exec("unrar x ".$target_file." ".$uncompressFolder);
      }else if($compressType == "7z"){
        exec("7z x ".$target_file." -o".$uncompressFolder);
      }else if($compressType == "php"){
        exec("mkdir ".$uncompressFolder."; cp ".$target_file." ".$uncompressFolder);
      }else{
        // die();
      }
      // setcookie("checksum", $fileCheckSum, time() + (86400), "/"); #ONE DAY COOKIE
      setcookie("fileID", $newFilename, time() + (86400/2), "/"); #HALF DAY COOKIE
      setcookie("fileName", $filename, time() + (86400/2), "/"); #HALF DAY COOKIE
      echo $uploadOk;
    }
  }
?>