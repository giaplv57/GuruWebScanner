<!doctype html>
<html>
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
		<!-- Apple devices fullscreen -->
		<meta name="apple-mobile-web-app-capable" content="yes" />
		<!-- Apple devices fullscreen -->
		<meta names="apple-mobile-web-app-status-bar-style" content="black-translucent" />
		
		<title>GuruWS :: Free online greybox web scanner</title>

		<!-- Bootstrap -->
		<link rel="stylesheet" href="css/bootstrap.min.css">
		<!-- Bootstrap responsive -->
		<link rel="stylesheet" href="css/bootstrap-responsive.min.css">
		<!-- Theme CSS -->
		<link rel="stylesheet" href="css/style.css">
		<!-- Color CSS -->
		<link rel="stylesheet" href="css/themes.css">


		<!-- jQuery -->
		<script src="js/jquery.min.js"></script>
		
		<!-- Nice Scroll -->
		<script src="js/plugins/nicescroll/jquery.nicescroll.min.js"></script>
		<!-- Bootstrap -->
		<script src="js/bootstrap.min.js"></script>

		<!--[if lte IE 9]>
			<script src="js/plugins/placeholder/jquery.placeholder.min.js"></script>
			<script>
				$(document).ready(function() {
					$('input, textarea').placeholder();
				});
			</script>
		<![endif]-->
		
		<!-- Favicon -->
		<link rel="shortcut icon" href="img/favicon.ico" />
		<!-- Apple devices Homescreen icon -->
		<link rel="apple-touch-icon-precomposed" href="img/apple-touch-icon-precomposed.png" />
	
	</head>

	<body>
		<?php include("connectdb.php"); ?>
		<div id="navigation">
			<div class="container-fluid">
				<a href="./"><img src="img/logowhite.png" alt="" class='retina-ready' width="200px"></a>				
			</div>
		</div>
		<hr/>
		
		<?php
		//For DEBUG purpose
		ini_set('display_errors',1); 
		error_reporting(E_ALL);
	    //////////////////////////////////

	    //Calculate folder size
	    function dirSize($directory) {
	    $size = 0;
	    foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory)) as $file){
	        $size+=$file->getSize();
	    }
	    	return $size;
		} 
		//////////////////////////////////

		$report = 0;

	    if (isset($_GET["id"])) {
	    	if(is_array($_GET["id"])) die();
	    	$con = ConnectDB() or die("can't connect to DB");
	    	$id = mysqli_real_escape_string($con, preg_replace('/\s+/', '', $_GET["id"])); //preg_replace to remove all space
	    	$query = mysqli_query($con,"SELECT * FROM reports WHERE id='$id'") or die(mysqli_error($con));
	    	$row = mysqli_fetch_array($query);
	        if(!empty($row['newFilename'])){
	        	$filename = $row['filename'];
	        	$fileCheckSum = $row['sha1hash'];
	        	$scanTime = $row['scantime'];
	        	$newFilename = $row['newFilename'];

	        	$resultFile = "./userFiles/".$newFilename.".result";

				//nl2br function to end line as proper
				$resultContent = nl2br(htmlspecialchars(file_get_contents($resultFile))); 

				//The PREG_SET_ORDER flag to ensure result appropriately distribute to array
				preg_match_all('/^(.*?)VULNERABILITY FOUND ([\s\S]*?)----------/m', $resultContent, $matches, PREG_SET_ORDER);
				$report = 1;
			}
		}
		?>
		<?php if($report == 1){ ?>
		<div class="container-fluid" id="content">		
			<div id="main">
				<div class="container-fluid">				
					<div class="row-fluid">
						<div class="span10">
							<div class="box box-color box-bordered">
								<div class="box-title">								
									<h3><center>
										<i class="icon-table"></i>
										REPORT
										</center>
									</h3>								
								</div>
								<font size="2px" face="Verdana">
								<div class="box-content nopadding">
									<table class="table table-hover table-nomargin">
										<thead>
											<tr>
												<th>[+] File name:</th>
												<th>
													<font face="Consolas"><b>
														<?php echo $filename; ?>
													</b></font>
												</th>											
											</tr>
										</thead>
										<tbody>
											<tr>
												<td>[+] SHA-1 hash:</td>
												<td>
													<font face="Consolas"><b>
														<?php echo $fileCheckSum; ?>
													</b></font>
												</td>											
											</tr>
											<tr>
												<td>[+] Total scaned time:</td>
												<td>
													<font face="Consolas"><b>
														<?php echo $scanTime/1000; ?> second
													</b></font>
												</td>											
											</tr>										
											<tr>
												<td>[+] Total Found Vulnerabilities:</td>
												<td>
													<font face="Consolas"><b>
														<?php echo count($matches); ?> vulnerabilities
													</b></font>
												</td>											
											</tr>
											<?php 
											foreach ($matches as $value) {
	    										echo '<tr>
														<td></td>
														<td>
														<font face="Consolas"><b>';
	    										echo $value[0];
	    										echo '</b></font>
	    												</td>											
														</tr>';
											}
											?>
										</tbody>
									</table>								
									<hr/>
									<!-- <div align="center">
										<form action="" class='form-horizontal'>									
										<button name="rescan" type='submit' class='btn btn btn-success'><i class="icon-search"></i> RESCAN</button>								
										<button name="print" type='submit' class='btn btn btn-primary'>PRINT <i class="icon-print"></i></button>				
										</form>
									</div> -->
								</div>							
							</div>
							</font>
						</div>
					</div>				
				</div>
			</div>
		</div>
		<?php } ?>
		<hr/>
		<div id="footer">
			<div class="container">
			<p>Powered by GuruWS Team<span class="font-grey-4">|</span> <a href="#">Contact</a> <span class="font-grey-4">|</span> <a href="#">Donate</a> 
			</p>
			</div>
			<a href="#" class="gototop"><i class="icon-arrow-up"></i></a>
		</div>
		
	</body>

</html>

