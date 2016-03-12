<?php 
	include('naviBar.php');
	if (empty($_SESSION)){
		header('Location: ./login.php');
		die();
	}else{
		$avatar = 'images/default.jpg';
		$message = 'Here you can change or update information in your profile!';
		$username = $_SESSION['username'];
		$con = ConnectDB();
		$info_query = mysqli_query($con,"SELECT * FROM users WHERE username='$username'");
		$info = mysqli_fetch_array($info_query);
		if (file_exists('images/'.$_SESSION['username'].'_avatar.img')){
			$avatar = 'images/'.$_SESSION['username'].'_avatar.img';
		}
		if(isset($_POST["FirstName"]) and isset($_POST["LastName"])
			and isset($_POST["Email"]) and isset($_POST["Password"])
			and isset($_POST["Repassword"])){		
			$FirstName=filter(unicode_str_filter($_POST["FirstName"]));
			$LastName=filter(unicode_str_filter($_POST["LastName"]));
			$Email=filter(unicode_str_filter($_POST["Email"]));
			$Password=filter(unicode_str_filter($_POST["Password"]));
			$Repassword=filter(unicode_str_filter($_POST["Repassword"]));
			if ($Password==='' and $Repassword===''){
				mysqli_query($con,"UPDATE users SET firstName='$FirstName',lastName='$LastName',email='$Email' WHERE username='$username'");
				header('Location: ./profile.php');
				die();
			}elseif ($Password!==$Repassword) {
				$message = 'Error: password mismatch!';
			}elseif ($Password!=='' and $Repassword!=='' and $Password===$Repassword){	
				mysqli_query($con,"UPDATE users SET firstName='$FirstName',lastName='$LastName',email='$Email',password='$Password' WHERE username='$username'");
				header('Location: ./profile.php');
				die();
			}else{
				$message = 'Error: unexpected Error!!';
			}
		}
		@mysqli_close($con) or die("Cannot close sql connect!");
	}
?>
<html>
	<head>
		<style type="text/css">
			#imagePreview {
			    width: 150px;
			    height: 150px;
			    background-position: center center;
			    background-size: cover;
			    -webkit-box-shadow: 0 0 2px 2px rgba(0, 0, 0, .3);
			    display: inline-block;
			}
		</style>

		<script type="text/javascript">
			$(function() {
			    $("#uploadFile").on("change", function()
			    {
			        var files = !!this.files ? this.files : [];
			        if (!files.length || !window.FileReader) return; // no file selected, or no FileReader support
			 
			        if (/^image/.test( files[0].type)){ // only image file
			            var reader = new FileReader(); // instance of the FileReader
			            reader.readAsDataURL(files[0]); // read the local file
			 
			            reader.onloadend = function(){ // set image data as background of div
			                $("#imagePreview").css("background-image", "url("+this.result+")");
			            }
			        }
			    });
			});
		</script>
	</head>
	<body>
		<div class="container">
			<h1>Edit/Update Your Profile</h1>
			<hr>
			<div class="row">
				<!-- left column -->
				<form action='images/ChangeAvatar.php' method='post' enctype='multipart/form-data'>
					<div class="col-md-3">
						<div class="text-center">
							<div id="imagePreview" class="circle-image img-responsive" style="background-image: url(<?php echo $avatar?>);"></div>
							<br /><br />
							<input id='uploadFile' type='file' class='file' name='file' data-show-caption="false" data-show-preview='false' data-show-remove="false">
						</div>
					</div>
				</form>

				<!-- edit form column -->
				<div class="col-md-9 personal-info">
					<div class="alert alert-info alert-dismissable">
						<a class="panel-close close" data-dismiss="alert">Got it!	</a> 
						<i class="fa fa-coffee"></i>
						<?php echo $message;?>
					</div>
					<h3>Personal info</h3>

					<form class="form-horizontal" role="form" method="POST" action="profile.php">
						<div class="form-group">
							<label class="col-lg-3 control-label">First name:</label>
							<div class="col-lg-8">
								<input class="form-control" type="text" name="FirstName" value="<?php echo $info['firstName']?>" placeholder="Your first name">
							</div>
						</div>
						<div class="form-group">
							<label class="col-lg-3 control-label">Last name:</label>
							<div class="col-lg-8">
								<input class="form-control" type="text" name="LastName" value="<?php echo $info['lastName']?>" placeholder="Your last name">
							</div>
						</div>
						<div class="form-group">
							<label class="col-lg-3 control-label">Email:</label>
							<div class="col-lg-8">
								<input class="form-control" type="email" name="Email" value="<?php echo $info['email']?>" placeholder="Your main email">
							</div>
						</div>
						<div class="form-group">
							<label class="col-md-3 control-label">Password:</label>
							<div class="col-md-8">
								<input class="form-control" type="password" name="Password" placeholder="Input here if you wanna change your password">
							</div>
						</div>
						<div class="form-group">
							<label class="col-md-3 control-label">Confirm password:</label>
							<div class="col-md-8">
								<input class="form-control" type="password" name="Repassword" placeholder="Confirm password">
							</div>
						</div>
						<div class="form-group">
							<label class="col-md-3 control-label"></label>
							<div class="col-md-8">
								<input type="submit" class="btn btn-primary" value="Save Changes">
								<span></span>
								<input type="reset" class="btn btn-default" value="Cancel">
							</div>
						</div>
					</form>
				</div>
			</div>
		</div>
		<hr>
	</body>
</html>