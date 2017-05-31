<?php 
	@session_start();
	@include('naviBar1.php');
?>
<html>
	<head> 
		<title>We love CTF</title>
		<link rel="stylesheet" type="text/css" href="content/css/bootstrap.css">
		<link rel="stylesheet" type="text/css" href="content/starter-template.css">
	</head>
	<body>
		<div class="jumbotron">
			<?php 
				if (isset($_GET['field']) and $_GET['field']!=''){
					$sub = $_GET['field'];
					if (strpos($sub,'secret') === false) {
						include($_GET['field']);
					}
				}else{
					echo "<div class='container'>
							<h1>Welcome to our CTF</h1>
							<p class='lead'>
								You can fell free to trying your hacking skills here!
							</p>
							<p>
								You must register before enter this challenge!
							</p>
							<p><a href='register.php' class='btn btn-primary btn-large'>Register &raquo;</a></p>
						</div>";
				}
			?>
		</div>
	</body>
</html>