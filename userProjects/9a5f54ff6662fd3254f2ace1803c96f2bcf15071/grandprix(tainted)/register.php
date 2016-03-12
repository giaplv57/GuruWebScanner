<html>
	<body>
		<center>
			<div>
				<h3 class="form-signin-heading">Members registration page</h3>
				<form class="form-inline" role="form" method="POST" action="register.php">
					<div class="form-group">
						<input type="text" name="username" class="form-control" placeholder="Enter Username">
					</div>
					<button type="submit" class="btn btn-success">Register</button>
				</form>
			</div>
		</center>
	</body>
</html>

<?php
	include("naviBar.php");
	if(isset($_POST["username"])){
		$password = substr(str_shuffle(md5(time())),0,15);
		$username = unicode_str_filter($_POST["username"]);
		$username = filter($username);
		if ($username!==''){
			$con = ConnectDB();
			$check = mysqli_query($con,"SELECT id FROM `users` WHERE username='$username'");

			if(mysqli_num_rows($check) == 0){
			    mysqli_query($con,"INSERT INTO users (username, password) VALUES ('$username', '$password')");
				echo '<div class="alert alert-success col-md-8 col-md-offset-2" role="alert">
					  	<center>
					  		<strong>Success!</strong>
					  	 	 Your username is: \''.$username.'\', your password is: \''.$password.'\'
					  	 	 <br>
					  	 	 You can login to enjoy our service now!!!
					  	</center>
					  </div>';
			}else {
			    echo '<div class="alert alert-danger col-md-6 col-md-offset-3" role="alert">
					  	<center>
						  	<strong>Error!</strong>
						  	 Username already exists.
					  	</center>
					  </div>';
			}
			@mysqli_close($con) or die("Cannot close sql connect!");
		}
	}

?>

