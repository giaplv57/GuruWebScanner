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

		<script type="text/javascript">

		    function PreviewImage() {
		        var oFReader = new FileReader();
		        oFReader.readAsDataURL(document.getElementById("sourcecode").files[0]);

		        oFReader.onload = function (oFREvent) {
		            document.getElementById("uploadPreview").value = "Press scan button..." //oFREvent.target.result;
		        };
		    };

		</script>
	</head>
	<body class='error'>		
		<div class="container-fluid" id="content">
			<div class="wrapper">		
				<div class="code" align="center">
					<img src="img/logo.png" alt="" class='retina-ready' width="380">
				</div>				
				<div class="desc" align="center">
					<font size="3px">
						Free online greybox web scanner
					</font>
				</div>
				<hr/>
				<form action="result.php" class='form-horizontal' method="post" enctype="multipart/form-data">
					<div class="input-append">
						<input type="text" name="search" id="uploadPreview" placeholder="Select a compressed file...">						
						<span class="btn btn-file">
							<span class="fileupload-new">
								<i class="icon-folder-close"></i>
							</span>
							<input type="file" name="userFile" id="sourcecode" onchange="PreviewImage();" />
						</span>
					</div>
					<br><br>
					<div class="buttons" align="center">
						<div class="pull-center">
							<button class="btn btn-success btn" type="submit" name="submit">SCAN <i class="icon-search"></i></button>
						</div>
					</div>
				</form>			
			</div>
		</div>
		<div id="footer">
			<div class="container">
			<p>Powered by GuruWS Team<span class="font-grey-4">|</span> <a href="#">Contact</a> <span class="font-grey-4">|</span> <a href="#">Donate</a> 
			</p>
			</div>
			<a href="#" class="gototop"><i class="icon-arrow-up"></i></a>
		</div>
	</body>
</html>
