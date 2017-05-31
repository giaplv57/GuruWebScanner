<?php 
	include("navi_bar.php");
	$db_username="root";
	$db_password="root";
	$database="contest8";
	$con=mysqli_connect('127.0.0.1', $db_username, $db_password, $database);
	$query = mysqli_query($con, "SELECT * FROM notes where id=".(int)$_GET['id']);
	$note = mysqli_fetch_array($query);
?>

<html>
	<head>
		<style type="text/css">
			.featurette-divider {
				margin: 40px 0; /* Space out the Bootstrap <hr> more */
			}
		</style>
	</head>
	<body>
		<div class="col-md-6 col-md-offset-1">
			<?php 
				echo '<h2>'.$note['title'].'</h2>';
				echo $note['content'];
				echo '<font color = "white">aa</font>';
				echo '<hr style="margin: 40px 0;">';
				echo '<h4>Source: </h4>';
				echo '<a href="'.$note['source'].'">'.$note['source'].'</a>';
				echo '<font color = "white">aa</font>';
				echo '<hr style="margin: 40px 0;">';
			?>	
		</div>		
	</body>      
</html>