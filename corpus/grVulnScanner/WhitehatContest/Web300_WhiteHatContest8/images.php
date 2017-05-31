<?php
	include("navi_bar.php");
?>
<html>
	<head>
		<style>
			body{
				background-color: #eee;
				padding-top: 50px;
			}
		</style>
	</head>
	<body>
		<center>
			<div id="carousel-example-generic" class="carousel slide" data-ride="carousel">
				<!-- Indicators -->
				<ol class="carousel-indicators">
					<?php
						if(!isset($_GET['album'])){
							header("Location: images.php?album=dogs");
							die();
						}
						$imgList = array();
						$linecount = 0;
						$file="images/".$_GET['album'];
						if (!is_file($file) or strpos($file,'.php') !== false){
							header("Location: images.php?album=dogs");
							die();
						}
						$handle = fopen($file, "r");
						while(!feof($file)){
						  $line = fgets($file);
						  array_push($imgList, $line);
						  $linecount++;
						}
						fclose($handle);
						echo '<li data-target="#carousel-example-generic" data-slide-to="0" class="active"></li>';
						for ($i = 2; $i <= $linecount; $i++){
							echo '<li data-target="#carousel-example-generic"></li>';
						}
						echo '</ol>
							<div class="carousel-inner">
								<div class="item active">
									<img src="'.$imgList[0].'" alt="..." class="img-responsive"">
									<div class="carousel-caption">
										<h3>Picure in '.$_GET['album'].' album.</h3>
										<p>Have a fun time!</p>
									</div>
								</div>';
						unset($imgList[0]);
						foreach ($imgList as $imgLink){
							echo '<div class="item">
										<img src="'.$imgLink.'" alt="..." class="img-responsive"">
										<div class="carousel-caption">
											<h3>Picure in '.$_GET['album'].' album.</h3>
											<p>Have a fun time!</p>
										</div>
									</div>';
						}
					?>	
				</div>

				<!-- Controls -->
				<a class="left carousel-control" href="#carousel-example-generic" role="button" data-slide="prev"">
					<span class="glyphicon glyphicon-chevron-left"></span>
				</a>
				<a class="right carousel-control" href="#carousel-example-generic" role="button" data-slide="next"">
					<span class="glyphicon glyphicon-chevron-right"></span>
				</a>
			</div>
			<ul class="pagination" style="margin-top: 3px;margin-bottom:-10px;">
			  <li><a href="images.php?album=dogs">My Dogs</a></li>
			  <li><a href="images.php?album=love">Love Stuff</a></li>
			  <li><a href="images.php?album=galaxy">Beautiful Universer</a></li>
			</ul>
		</center>
	</body>
</html>