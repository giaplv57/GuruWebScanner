<html>
	<head> 
		<link rel="stylesheet" type="text/css" href="../content/css/bootstrap.css">
		<link rel="stylesheet" type="text/css" href="../content/starter-template.css">
	</head>
	<body>
		<div class="starter-template">
			<h3 class="form-signin-heading">Admin login page</h3>
			<form class="form-horizontal" role="form" method="POST" action="login.php">
				<div class="form-group">
					<label class="col-md-5 control-label">Username:</label>
					<div class="col-md-3">
						<input class="form-control" type="text" name="username" placeholder="Username">
					</div>
				</div>
				<div class="form-group">
					<label class="col-md-5 control-label">Password:</label>
					<div class="col-md-3">
						<input class="form-control" type="password" name="password" placeholder="Password">
					</div>
				</div>
				<div class="form-group">
					<div class="col-md-offset-3 col-md-8">
						<button type="submit" class="btn btn-success">Sign in</button>
					</div>
				</div>
			</form>
		</div>
		<!-- register.php-->
	</body>
</html>
<?php
	include("../navi_bar.php");
	include("validate.php");
	if(isset($_POST["username"]) and isset($_POST["password"])){
		$db_username="root";
		$db_password="root";
		$database="contest8";
		$username = $_POST["username"];
		$password = $_POST["password"];
		if (block_filter($username)){
			echo '<div class="alert alert-danger col-md-6 col-md-offset-3" role="alert">
					  	<center>
						  	<strong>Hacker detected!</strong>
					  	</center>
					</div>';
		}else{
			@$con=mysqli_connect('127.0.0.1', $db_username, $db_password, $database) or die("Unable to connect database");
			@$query1 = mysqli_query($con, "SELECT * FROM `users` where username = \"".addslashes($username)."\"") or die("Error on database. Error number 1");
			$row1 = mysqli_fetch_array($query1);
			if(!empty($row1['username']) AND !empty($row1['password'])){
				@$query2 = mysqli_query($con, "SELECT * FROM `users` where username = '$username' AND password = '$password'") or die("Error on database. Error number 2");
				$row2 = mysqli_fetch_array($query2);
			
				if(!empty($row2['username']) AND !empty($row2['password'])){
					if($row2['active']<1){
						echo '<div class="alert alert-danger col-md-6 col-md-offset-3" role="alert">
							  	<center>
								  	<strong>Yep!</strong>
								  	 your account is not active yet.
							  	</center>
							</div>';
					}
					elseif($row2['active']==1){
						echo '<div class="alert alert-success col-md-6 col-md-offset-3" role="alert">
							  	<center>
							  		<strong>Awesome!</strong>
							  	 	 Here is you flag: "t0_1nf1n1ty_4nd_b3y0nd!".
							  	</center>
							  </div>';
					}else{
						echo '<div class="alert alert-danger col-md-6 col-md-offset-3" role="alert">
							  	<center>
								  	<strong>Unexpected error!</strong>
							  	</center>
							</div>';
					}
				}else{
					echo '<div class="alert alert-danger col-md-6 col-md-offset-3" role="alert">
						  	<center>
							  	<strong>Error!</strong>
							  	 Your password is not incorrect!
						  	</center>
						</div>';
				}
				@mysqli_close($con);
			}else{
				echo '<div class="alert alert-danger col-md-6 col-md-offset-3" role="alert">
						  	<center>
							  	<strong>Error!</strong>
							  	 Username is not exists!
						  	</center>
						</div>';
			}
		}
	}
?>

