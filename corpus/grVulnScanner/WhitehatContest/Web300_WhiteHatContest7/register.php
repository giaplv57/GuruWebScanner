<?php 
	@session_start();
	include('validate.php');
?>
<html>
	<head> 
		<title>We love CTF</title>
		<link rel="stylesheet" type="text/css" href="content/css/bootstrap.css">
		<link rel="stylesheet" type="text/css" href="content/starter-template.css">
	</head>
	<body>
		<div class='navbar navbar-inverse navbar-fixed-top' role='navigation'>
			<div class='container'>
				<div class='navbar-header'>
					<button type='button' class='navbar-toggle' data-toggle='collapse' data-target='.navbar-collapse'>
						<span class='sr-only'>Toggle navigation</span>
						<span class='icon-bar'></span>
						<span class='icon-bar'></span>
						<span class='icon-bar'></span>
					</button>
					<a class='navbar-brand' href='#'>WhiteHat_CTF</a>
				</div>
				<div class='collapse navbar-collapse'>
					<ul class='nav navbar-nav'>
						<li><a href='index.php'>Home</a></li>
						<li><a href='register.php'>Register</a></li>
						<li><a href='login.php'>Login</a></li>
						<li><a href='index.php?field=about.php'>About</a></li>
					</ul>
				</div><!--/.nav-collapse -->
			</div>
		</div>
		<div class="starter-template">
			<form class="form-horizontal" role="form" method="POST" action="register.php">
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
						<button type="submit" class="btn btn-default">Register</button>
					</div>
				</div>
			</form>
		</div>
	</body>
</html>
<?php
	if(isset($_POST["username"]) and isset($_POST["password"])){
		$db_username="root";
		$db_password="root";
		$database="whitehat_ctf";
		$username = $_POST["username"];
		$password = $_POST["password"];

		function block_filter($input){
			$input1 = strtolower($input);
			$blacklist = ARRAY ("insert", "select", "update", "delete", "distinct", "having", "truncate", "replace", "union", "handler", "like", "substring", "mid", "or ", "procedure", "limit", "order by", "group by", "union", "table", "outfile", "dumpfile", "load_file");
            foreach ($blacklist as $word){
	            if (strpos($input1,$word) !== false) {
				    return true;
				}
			}
			return false;
		}
		if (block_filter($username) or block_filter($password)){
			echo 'Hacker detected!';
		}else{
			@$con=mysqli_connect('127.0.0.1', $db_username, $db_password, $database) or die("Unable to connect database");
			$username = filter($username);
			$password = filter($password);
			$check = mysqli_query($con,"SELECT id FROM `users` WHERE username='$username'");

			if(mysqli_num_rows($check) == 0) {
			    mysqli_query($con,"INSERT INTO users (username, password, role) VALUES ('$username', '$password', 0)");
				echo 'SUCCESS!!!';
			} else {
			    echo 'ERROR!!! 	Username already exits!';
			}
			@mysqli_close($con);
		}
	}
?>