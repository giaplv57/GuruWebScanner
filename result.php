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
	<!-- jQuery UI -->
	<link rel="stylesheet" href="css/plugins/jquery-ui/smoothness/jquery-ui.css">
	<link rel="stylesheet" href="css/plugins/jquery-ui/smoothness/jquery.ui.theme.css">
	<!-- Theme CSS -->
	<link rel="stylesheet" href="css/style.css">
	<!-- Color CSS -->
	<link rel="stylesheet" href="css/themes.css">


	<!-- jQuery -->
	<script src="js/jquery.min.js"></script>
	
	<!-- Nice Scroll -->
	<script src="js/plugins/nicescroll/jquery.nicescroll.min.js"></script>
	<!-- imagesLoaded -->
	<script src="js/plugins/imagesLoaded/jquery.imagesloaded.min.js"></script>
	<!-- jQuery UI -->
	<script src="js/plugins/jquery-ui/jquery.ui.core.min.js"></script>
	<script src="js/plugins/jquery-ui/jquery.ui.widget.min.js"></script>
	<script src="js/plugins/jquery-ui/jquery.ui.mouse.min.js"></script>
	<script src="js/plugins/jquery-ui/jquery.ui.resizable.min.js"></script>
	<script src="js/plugins/jquery-ui/jquery.ui.sortable.min.js"></script>
	<!-- slimScroll -->
	<script src="js/plugins/slimscroll/jquery.slimscroll.min.js"></script>
	<!-- Bootstrap -->
	<script src="js/bootstrap.min.js"></script>
	<!-- Bootbox -->
	<script src="js/plugins/bootbox/jquery.bootbox.js"></script>
	<!-- Bootbox -->
	<script src="js/plugins/form/jquery.form.min.js"></script>
	<!-- Validation -->
	<script src="js/plugins/validation/jquery.validate.min.js"></script>
	<script src="js/plugins/validation/additional-methods.min.js"></script>

	<!-- Theme framework -->
	<script src="js/eakroko.min.js"></script>
	<!-- Theme scripts -->
	<script src="js/application.min.js"></script>
	<!-- Just for demonstration -->
	<script src="js/demonstration.min.js"></script>

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
	<div id="navigation">
		<div class="container-fluid">
			<img src="img/logowhite.png" alt="" class='retina-ready' width="200px">						
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

    if (isset($_POST["submit"])) {
    	$report 	  = 0;
    	$scanTime 	  = 0;
        $target_dir   = "./userFiles/";
        $compressType = pathinfo($_FILES["userFile"]["name"], PATHINFO_EXTENSION);
		$fileCheckSum = sha1_file($_FILES["userFile"]["tmp_name"]);
        $target_file  = $target_dir . $fileCheckSum . "." . $compressType;
        $uploadOk     = 1;

        // Check if file already exists
        if (file_exists($target_file)) {
            echo '<div class="alert alert-warning col-md-4" role="alert">Error! File already exists.</div>';
            $uploadOk = 0;
        }
        // Check file size
        if ($_FILES["userFile"]["size"] > 104857600) { //100MB limited
        	echo '<div class="alert alert-warning col-md-4" role="alert">Error! Your file is too large.</div>';
            $uploadOk = 0;
        }
        // Allow certain file formats
        if ($compressType != "tar" && $compressType != "zip" && $compressType != "rar") {
        	echo '<div class="alert alert-warning col-md-4" role="alert">Error! Only tar, zip or rar file is allowed.</div>';
            $uploadOk = 0;
        }
        // Check if $uploadOk is set to 0 by an error

        if ($uploadOk == 0 || !move_uploaded_file($_FILES["userFile"]["tmp_name"], $target_file)){
        	echo '<div class="alert alert-danger" role="alert">Sorry, there was errors while uploading your file.</div>';
        }else{
        	$startTime = round(microtime(true) * 1000);
        	mkdir("userFiles/" . $fileCheckSum, 0777); //can't create contain folder and extract tar file in 1 command
        	$uncompressFolder = "./userFiles/".$fileCheckSum."/";
            if($compressType == "tar"){ 	
				exec("tar -xf ".$target_file." -C ".$uncompressFolder);
            }else if($compressType == "zip"){
            	exec("unzip ".$target_file." -d ".$uncompressFolder);
            }else if($compressType == "rar"){
            	exec("unrar -x ".$target_file." ".$uncompressFolder);
            }else{
            	die();
            }
            if (file_exists($uncompressFolder) && dirSize($uncompressFolder) > 0){ //Ready for scan
            	$resultFile = "./userFiles/".$fileCheckSum.".result";
				$command = "for f in \$(find ".$uncompressFolder." -name '*.php'); do php ./scanner/Main.php \$f; done > ".$resultFile;
				system($command);
				$resultContent = nl2br(htmlspecialchars(file_get_contents($resultFile))); //nl2br function to end line as proper

				//The PREG_SET_ORDER flag to ensure result appropriately distribute to array
				preg_match_all('/^(.*?)VULNERABILITY FOUND ([\s\S]*?)----------/m', $resultContent, $matches, PREG_SET_ORDER);
				$report = 1;
				$stopTime = round(microtime(true) * 1000);
				$scanTime = $stopTime - $startTime;
			}else{
				echo "There are problems with your compress file or it's empty.</br>";
			}
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
													<?php echo $_FILES["userFile"]["name"]; ?>
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
										<tr>
											<td>[+] Link to share:</td>											
											<td>
												<font face="Consolas"><b>
													http://guru.ws/share.php?checkSum=<?php echo $fileCheckSum ?>
												</b></font>
											</td>											
										</tr>
									</tbody>
								</table>								
								<hr/>
								<div align="center">
									<form action="" class='form-horizontal'>									
									<button name="rescan" type='submit' class='btn btn btn-success'><i class="icon-search"></i> RESCAN</button>								
									<button name="print" type='submit' class='btn btn btn-primary'>PRINT <i class="icon-print"></i></button>				
								</form>
							</div>
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

