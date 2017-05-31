<?php
	@session_start();
	$fa=0;
	if(!isset($_SESSION['username']) || (trim($_SESSION['username']) == '')) {
		echo '<script language="javascript">';
		echo 'alert("Login to enter this site!!")';
		echo '</script>';
		
		echo '<script language="javascript">';
		echo 'window.location = "login.php"';
		echo '</script>';
	}

	if(isset($_SESSION['username']) and isset($_POST["groupCode"]) and isset($_POST["data"])){
		include ('key/secretK3y.php');
		$groupCode = $_POST["groupCode"];
		@$data = unserialize($_POST["data"]);
		
		if ($data == md5($secret)){
			$db_username="root";
			$db_password="root";
			$database="whitehat_ctf";
			$username = $_SESSION['username'];

			@$con=mysqli_connect('127.0.0.1', $db_username, $db_password, $database) or die("Unable to connect database");
			@$query = mysqli_query($con, "UPDATE users SET role=1 WHERE username='$username'") or die("Error on database");
			mysqli_close($con);
			$fa=1;
		}
		else
			$fa=2;
	}
?>

<html>
	<head> 
		<title>Two step authorization!</title>
		<script src="javascript/serialize.js"></script>
	</head>
	<body>
		<?php
			include ('naviBar.php');
		?>
		<div class="starter-template">
			<form class="form-horizontal" role="form" method="POST" action="4dm1n_l0g1n_1.php" id="form">
				<h2>Input the secret group code to overcome!</h2>
				<div class="form-group">
					<div class="col-md-offset-4 col-md-4">
						<input class="form-control" type="text" name="groupCode" id="groupCode" placeholder="Secret">
						<input type="hidden" name="data" id="data" value="">
					</div>
				</div>
				<div class="form-group">
					<div class="col-md-offset-2 col-md-8">
						<button type="submit" class="btn btn-default" onclick='serial_input();'>OK!</button>
					</div>
				</div>
				<!--74W5P,W)?;#!G,6Y?;#-V,VQ?,BYP:'``-->
			</form>
		</div>

		<?php
			if ($fa==1)
				echo "<h3 style = 'text-align:center; color: red'>YEP! You did it!!</h3>"; 
			elseif ($fa==2) 
				echo "<h4 style = 'text-align:center; color: blue'>Noob!</h4>";
		?>
	</body>
</html>