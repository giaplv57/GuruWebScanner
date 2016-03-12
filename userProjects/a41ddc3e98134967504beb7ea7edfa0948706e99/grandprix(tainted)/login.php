<html>
	<body>
		<center>
			<div>
				<h3 class="form-signin-heading">Members login page</h3>
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
						<div class="col-md-offset-3 col-md-8 row">
							<a class="btn btn-success" href="register.php">Register</a>
							<button type="submit" class="btn btn-success">Sign in</button>
						</div>
					</div>
				</form>
			</div>
		</center>
	</body>
</html>
<?php
	include("naviBar.php");
	if(isset($_POST["username"]) and isset($_POST["password"])){
		$username = filter($_POST["username"]);
		$password = filter($_POST["password"]);
		if ($username!=='' and $password!==''){
			ob_start();
			$con = ConnectDB();
			$query = mysqli_query($con, "SELECT * FROM `users` where username = '$username' AND password = '$password'");
			$row = mysqli_fetch_array($query);
			if(!empty($row['username']) AND !empty($row['password']) AND $row['status']==='1') {
				session_regenerate_id();
				$_SESSION['username'] = $row['username'];
				$_SESSION['role'] = $row['role'];
				session_write_close();
				header('Location: index.php');
				die();
			}elseif (!empty($row['username']) AND !empty($row['password']) AND $row['status']==='0') {
				echo '<div class="alert alert-danger col-md-6 col-md-offset-3" role="alert">
					  	<center>
						  	<strong>Your account was blocked!</strong>
						  	<br />
						  	Contact admins if you have any question.
					  	</center>
					</div>';
			}
			else{
				echo '<div class="alert alert-danger col-md-6 col-md-offset-3" role="alert">
					  	<center>
						  	<strong>Wrong username of password!</strong>
					  	</center>
					</div>';
			}
			@mysqli_close($con) or die("Cannot close sql connect!");
		}
	}
?>

