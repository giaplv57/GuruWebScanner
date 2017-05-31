<html>
	<head> 
		<title>Two step authorization!</title>
	</head>
	<body>
		<div class="starter-template">
			<form class="form-horizontal" role="form" method="GET" action="Sup3r_l0g1n_l3v3l_2.php">
				<h2>Admin Login page<br><br></h2>
				<div class="form-group">
					<label class="col-md-5 control-label">Username:</label>
					<div class="col-md-3">
						<input class="form-control" type="text" name="username" placeholder="Username" id="username" >
					</div>
				</div>
				<div class="form-group">
					<label class="col-md-5 control-label">Password:</label>
					<div class="col-md-3">
						<input class="form-control" type="password" name="password" placeholder="Password" id="password" >
					</div>
				</div>
				<div class="form-group">
					<div class="col-md-offset-3 col-md-8">
						<button type="submit" class="btn btn-default">Get Flag!!</button>
					</div>
				</div>
			</form>
		</div>
	</body>
</html>

<?php 
	@session_start();
	include('naviBar.php');
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

	if(!isset($_SESSION['username']) || (trim($_SESSION['username']) == '')) {
		echo '<script language="javascript">';
		echo 'alert("Login to enter this site!!")';
		echo '</script>';
		
		echo '<script language="javascript">';
		echo 'window.location = "login.php"';
		echo '</script>';
	}else{
		$db_username="root";
		$db_password="root";
		$database="whitehat_ctf";
		$ses_username = $_SESSION['username'];
		@$con=mysqli_connect('127.0.0.1', $db_username, $db_password, $database) or die("Unable to connect database");
		@$query = mysqli_query($con, "SELECT role FROM `users` where username = '$ses_username'") or die("Error on database");
		$row = mysqli_fetch_array($query);
		$role = $row['role'];
		if ($role < 1){
			echo '<script language="javascript">';
			echo 'alert("Your privilege is not enough!!")';
			echo '</script>';

			echo '<script language="javascript">';
			echo 'window.location = "index.php"';
			echo '</script>';
		}else{
			if(isset($_GET["username"]) and isset($_GET["password"])){
				$check_privilege = 'Always';
				extract ($_GET);
				if (block_filter($username) or block_filter($password)){
					echo 'Hacker detected!';
				}else{
					if($check_privilege !== 'Always' and $role == 1){
						@$query_2 = mysqli_query($con, "UPDATE users SET role=2 WHERE username='$ses_username'") or die("Error on database");
					}else{
						
						$username = filter($username);
						$password = filter($password);
						@$query_2 = mysqli_query($con, "SELECT * FROM `users` where username = '$username' and password = '$password'") or die("Error on database");
						$row_2 = mysqli_fetch_array($query_2);

						if(!empty($row_2['username']) AND !empty($row_2['password'])) {
							$role_2 = $row['role'];
							if ($role_2 == 2){
								include ('fl4g/secretfl4g.php');
								echo $secret_flag;
							}
						}else{
							echo "SORRY... YOU INPUT WRONG ID AND PASSWORD... PLEASE RETRY..."; 
						}
					}
				}
			}

		}
		@mysqli_close($con);
	}
?>

