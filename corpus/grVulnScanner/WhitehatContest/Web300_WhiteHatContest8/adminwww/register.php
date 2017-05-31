<html>
	<head> 
		<link rel="stylesheet" type="text/css" href="../content/css/bootstrap.css">
		<link rel="stylesheet" type="text/css" href="../content/starter-template.css">
	</head>
	<body>
		<div class="starter-template">
			<h3 class="form-signin-heading">Admin registration page</h3>
			<form class="form-inline" role="form" method="POST" action="register.php">
				<div class="form-group">
					<input type="text" name="username" class="form-control" placeholder="Enter Username">
				</div>
				<button type="submit" class="btn btn-success">Register</button>
			</form>
		</div>
	</body>
</html>

<?php
	include("secret.php");
	include("../navi_bar.php");
	include("validate.php");
	if(isset($_POST["username"])){
		$db_username="root";
		$db_password="root";
		$database="contest8";
		$admin_password = $secret_passwd;
		$username = $_POST["username"];
		if (block_filter($username) or $username===''){
			echo '<div class="alert alert-danger col-md-6 col-md-offset-3" role="alert">
					  	<center>
						  	<strong>Hacker detected!</strong>
					  		<br></br>
					  		<a>For the sake of your account, i suggest you use alphabet characters and numbers.</a>
					  	</center>
					</div>
					<!--Black list: ("insert", "select", "update", "delete", "distinct", "having", "truncate", "replace", "union", "handler", "like", "substring", "mid", "procedure", "limit", "order by", "group by", "union", "table", "outfile", "dumpfile", "load_file", "\'", """, "<", ">", " ")-->';
		}else{
			@$con=mysqli_connect('127.0.0.1', $db_username, $db_password, $database) or die("Unable to connect database");
			$username_db = add_addition_db($username);
			$username = add_addition_noti($username);
		
			$check = mysqli_query($con,"SELECT id FROM `users` WHERE username='$username_db'");

			if(mysqli_num_rows($check) == 0){
			    mysqli_query($con,"INSERT INTO users (username, password) VALUES ('$username_db', '$admin_password')");
				echo '<div class="alert alert-success col-md-8 col-md-offset-2" role="alert">
					  	<center>
					  		<strong>Success!</strong>
					  	 	 Your username is: \''.$username.'\', your password is: \''.$admin_password.'\', meet me to active your account before using.
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

