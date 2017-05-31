<?php 
	include("navi_bar.php");
	$db_username="root";
	$db_password="root";
	$database="contest8";
	$con=mysqli_connect('127.0.0.1', $db_username, $db_password, $database) or die("Unable to connect database");
	$query = mysqli_query($con, "SELECT * FROM notes");
	$notes = array();
	while($row = mysqli_fetch_assoc($query)){
		$notes[] = $row;
	}
?>

<html>
	<body>
		<head>
			<style type="text/css">
				.featurette-divider {
					margin: 80px 0; /* Space out the Bootstrap <hr> more */
				}
			</style>
		</head>
		<div class="jumbotron" style="margin-top:-20">
			<div class="container">
				<h1>Yup!</h1>
				<p>Here is all of my important notes. Almost of theme are related to web security points or Capture The Flag challenges.</p>
				<p>Have a fun time!</p>
			</div>
		</div>
		<div class="container">
				<?php
					$count = 0;
					foreach ($notes as $row){
						if ($count % 3 ===0){
							echo '<div class="row">';
						}
						echo '<div class="col-lg-4">
							<img class="img-circle" src="images/'.$row['img'].'" alt="Generic placeholder image" style="width: 140px; height: 140px;">
							<h3>'.$row['title'].'</h3>
							<p><a class="btn btn-default" href="ViewNote.php?id='.$row['id'].'" role="button">View details &raquo;</a></p>
							</div><!-- /.col-lg-4 -->';
						if (($count+1)%3===0){
							echo '<font color = "white">aa</font>';
							echo '<hr style="margin: 40px 0;">';
						}
						$count++;
					}
				?>
			</div><!-- /.row -->
		</div>
	</body>      
</html>