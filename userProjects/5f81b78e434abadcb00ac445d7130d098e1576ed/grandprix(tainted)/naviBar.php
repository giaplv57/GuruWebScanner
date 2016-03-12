<?php
	include('validate.php');
	@session_start();
	$avatar = 'images/default.jpg';
	if (!empty($_SESSION) and file_exists('images/'.$_SESSION['username'].'_avatar.img')){
		$avatar = 'images/'.$_SESSION['username'].'_avatar.img';
	}
	function ConnectDB(){
		$db_username="root";
		$db_password="root";
		$database="contest8";
		$con=mysqli_connect('127.0.0.1', $db_username, $db_password, $database);
		return $con;
	}
?>

<html>
	<head>
	    <meta charset="utf-8" />
		<title>Welcome to Lightning Uploader!</title>
		<link rel="stylesheet" type="text/css" href="content/css/bootstrap.css">
		<link rel="stylesheet" type="text/css" href="content/theme.css">
		<link rel="stylesheet" type="text/css" href="content/css/circle-image.css">
		<link href="content/fileinput/css/fileinput.css" media="all" rel="stylesheet" type="text/css" />
		<script src="content/js/jquery.min.js"></script>
		<script src="content/js/bootstrap.js"></script>
		<script src="content/fileinput/js/fileinput.js" type="text/javascript"></script>
		<style>
			.img-responsive, .thumbnail > img, .thumbnail a > img, .carousel-inner > .item > img, .carousel-inner > .item > a > img {
			    display: inline;
			}
			.circle-image-nav{
				width:40px;
    			height:40px;
			}
			
		</style>
	</head>
	<body>
		<div style="text-align:center">
			<?php 
				if(isset($_SESSION['username']) and isset($_SESSION['role'])){
					$username = $_SESSION['username'];
					$role = $_SESSION['role'];
					if ($role === '0'){
						echo "<div class='navbar navbar-inverse navbar-fixed-top' role='navigation'>
								<div class='container'>
									<div class='navbar-header'>
										<button type='button' class='navbar-toggle' data-toggle='collapse' data-target='.navbar-collapse'>
											<span class='sr-only'>Toggle navigation</span>
											<span class='icon-bar'></span>
											<span class='icon-bar'></span>
											<span class='icon-bar'></span>
										</button>
										<a class='navbar-brand' href='index.php'>Lightning Speed Uploader</a>
									</div>
									<div class='collapse navbar-collapse'>
										<ul class='nav navbar-nav'>
											<li><a href='index.php'>Home</a></li>
											<li><a href='myfiles.php'>MyFiles</a></li>
											<li><a href='logout.php'>Logout</a></li>
										</ul>
										
										<ul class='nav navbar-nav navbar-right'>
											<img src='".$avatar."'class='img-responsive circle-image circle-image-nav' style='float:left; margin-top:5px;'/>
											<li><a href='profile.php'>Welcome $username</a></li>	
										</ul>
									</div><!--/.nav-collapse -->
								</div>
							</div>";
					}elseif ($role === '1'){
						echo "<div class='navbar navbar-inverse navbar-fixed-top' role='navigation'>
								<div class='container'>
									<div class='navbar-header'>
										<button type='button' class='navbar-toggle' data-toggle='collapse' data-target='.navbar-collapse'>
											<span class='sr-only'>Toggle navigation</span>
											<span class='icon-bar'></span>
											<span class='icon-bar'></span>
											<span class='icon-bar'></span>
										</button>
										<a class='navbar-brand' href='index.php'>Lightning Speed Uploader</a>
									</div>
									<div class='collapse navbar-collapse'>
										<ul class='nav navbar-nav'>
											<li><a href='index.php'>Home</a></li>
											<li><a href='myfiles.php'>MyFiles</a></li>
											<li><a href='filemanager.php'>FileManager</a></li>
											<li><a href='usermanager.php'>UserManager</a></li>
											<li><a href='logout.php'>Logout</a></li>
										</ul>
										
										<ul class='nav navbar-nav navbar-right'>
											<img src='".$avatar."'class='img-responsive circle-image circle-image-nav' style='float:left; margin-top:5px;'/>
											<li><a href='profile.php'>Welcome $username</a></li>	
										</ul>
									</div><!--/.nav-collapse -->
								</div>
							</div>";
					}else{
						header("HTTP/1.0 404 Not Found");
						die();
					}
				}else
					echo "<div class='navbar navbar-inverse navbar-fixed-top' role='navigation'>
							<div class='container'>
								<div class='navbar-header'>
									<button type='button' class='navbar-toggle' data-toggle='collapse' data-target='.navbar-collapse'>
										<span class='sr-only'>Toggle navigation</span>
										<span class='icon-bar'></span>
										<span class='icon-bar'></span>
										<span class='icon-bar'></span>
									</button>
									<a class='navbar-brand' href='index.php'>Lightning Speed Uploader</a>
								</div>
								<div class='collapse navbar-collapse'>
									<ul class='nav navbar-nav'>
										<li><a href='index.php'>Home</a></li>
										<li><a href='register.php'>Register</a></li>
										<li><a href='login.php'>Login</a></li>
									</ul>
								</div><!--/.nav-collapse -->
							</div>
						</div>";
			?>
		</div>
	</body>
</html>