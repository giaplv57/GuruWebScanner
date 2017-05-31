<html>
	<head>
		<link rel="stylesheet" type="text/css" href="content/css/bootstrap.css">
		<link rel="stylesheet" type="text/css" href="content/starter-template.css">
	</head>
</html>

<?php
	include('validate.php');
?>
	

	<div style="text-align:center">
		<?php 
			if(isset($_SESSION['username'])) {
				$username = $_SESSION['username'];
				$username = filter($username);
				echo "<div class='navbar navbar-inverse navbar-fixed-top' role='navigation'>
					      <div class='container'>
					        <div class='navbar-header'>
					          <button type='button' class='navbar-toggle' data-toggle='collapse' data-target='.navbar-collapse'>
					            <span class='sr-only'>Toggle navigation</span>
					            <span class='icon-bar'></span>
					            <span class='icon-bar'></span>
					            <span class='icon-bar'></span>
					          </button>
					          <a class='navbar-brand' href='index.php'>WhiteHat_CTF</a>
					        </div>
					        <div class='collapse navbar-collapse'>
					          <ul class='nav navbar-nav'>
					            <li><a href='index.php'>Home</a></li>
								<li><a href='logout.php'>Logout</a></li>
								<li><a href='index.php?field=about.php'>About</a></li>
					          </ul>
					          <ul class='nav navbar-nav navbar-right'>
					          	<li><a href='#'>WELCOME $username</a></li>	
					          </ul>
					        </div><!--/.nav-collapse -->
					    </div>
					</div>";
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
					          <a class='navbar-brand' href='index.php'>WhiteHat_CTF</a>
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
					</div>";
		?>
	</div>