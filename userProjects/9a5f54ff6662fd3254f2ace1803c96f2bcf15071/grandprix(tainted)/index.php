<?php
	include('naviBar.php');
?>

<html>
	<head>
		<link rel="stylesheet" type="text/css" href="content/landing.css">
	</head>
	<body>
		<div class="site-wrapper">

			<div class="site-wrapper-inner">

				<div class="cover-container">
					<div class="masthead clearfix">
						<div class="inner cover">
							<h1 class="cover-heading">Welcome to Lightning Uploader.</h1>
							<p class="lead">Here you can upload your files into our server. The special thing about our service is that we will never erase your file!
								<br />
								<?php
									if(!isset($_SESSION['username'])){
										echo 'Excited enough? Join us now!</p>
											<p class="lead">
												<a href="./register.php" class="btn btn-lg btn-default">Register!</a>
											</p>';
									}else{
										echo 'At this time, we just support files which have size below 2MB</p><p class="lead">
												<a href="myfiles.php" class="btn btn-lg btn-default">My Files</a>
											</p>';
									}
								?>
						</div>
					</div>

				</div>
			</div>
		</div>
	</body>
</html>