<?php
	include('navibar.php');
	if (!empty($_FILES) & isset($_POST["filetype"]) & isset($_POST["filename"]) & isset($_SESSION['username'])){
		if ($_FILES["file"]["name"]===''){
			header('Location: ./myfiles.php');
			die();
		}else{
			$username = $_SESSION['username'];
			$con = ConnectDB();
			$query1 = mysqli_query($con, "SELECT id FROM `users` where username = '$username'");
			$row = mysqli_fetch_array($query1);
			$UserId = $row['id'];

			$BlackListExts = array("php", "html", "phtml");
			$Temp = explode(".", $_FILES["file"]["name"]);
			$Extension = end($Temp);
			$FileName = unicode_str_filter($_POST["filename"]).'.'.$Extension;
			$FileType = $_POST["filetype"];
			$FileSize = round($_FILES["file"]["size"]/1024, 2).' KB';
			$Location = "files/".$FileName;
			
			if (($_FILES["file"]["size"] < 2097152) && !in_array($Extension, $BlackListExts)) { #Max file size is 2 MB
				if ($_FILES["file"]["error"] > 0) {
					echo "Error!! Return Code: " . $_FILES["file"]["error"] . "<br>";
				}else{
					if (file_exists($Location)) {
      					echo '<div class="alert alert-danger col-md-6 col-md-offset-3" role="alert">
							  	<center>
								  	<strong>Error!</strong>
								  	'.$FileName.' already exists!.
							  	</center>
							  </div>';
    				}else{
						$query = mysqli_query($con,"INSERT INTO files (uid, filetype, filename, filesize, location) VALUES ($UserId, $FileType, '$FileName', '$FileSize', '$Location')");
						move_uploaded_file($_FILES["file"]["tmp_name"], $Location);
						header('Location: ./myfiles.php');
						die();
					}
				}
			}else{
				echo "Invalid file!";
			}
			@mysqli_close($con) or die("Cannot close sql connect!");
		}
	}
?>