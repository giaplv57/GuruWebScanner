<?php
	@session_start();
	if (!empty($_FILES)){
		if ($_FILES["file"]["name"]===''){
			header('Location: ./../profile.php');
			die();
		}else{
			$valid_mime_types = array("image/png","image/jpeg","image/pjpeg");
			$valid_file_extensions = array(".jpg", ".jpeg", ".png");
			$file_extension = strrchr(strtolower($_FILES["file"]["name"]), ".");

			if (in_array($_FILES["file"]["type"], $valid_mime_types) 
				and in_array($file_extension, $valid_file_extensions) 
				and @getimagesize($_FILES["file"]["tmp_name"]) !== false){
		    	$destination = $_SESSION['username'].'_avatar.img';
		    	move_uploaded_file($_FILES["file"]["tmp_name"], $destination);
		    	header('Location: ./../profile.php');
		    	die();
			}else{
				echo 'Invalid file!';
			}
		}
	}
?>