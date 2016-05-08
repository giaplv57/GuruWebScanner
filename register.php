<!doctype html>
<html>
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
		<!-- Apple devices fullscreen -->
		<meta name="apple-mobile-web-app-capable" content="yes" />
		<!-- Apple devices fullscreen -->
		<meta names="apple-mobile-web-app-status-bar-style" content="black-translucent" />
		
		<title>GuruWS :: Free online greybox web scanner :: Scan Vulnerability and Detect WebShell/Backdoor</title>

		<!-- Bootstrap -->
		<link rel="stylesheet" href="assets/css/bootstrap.min.css">
		<!-- Bootstrap responsive -->
		<link rel="stylesheet" href="assets/css/bootstrap-responsive.min.css">
		<!-- Theme CSS -->
		<link rel="stylesheet" href="assets/css/style.css">
		<!-- Color CSS -->
		<link rel="stylesheet" href="assets/css/themes.css">


		<!-- jQuery -->
		<script src="assets/js/jquery.min.js"></script>
		<!-- Nice Scroll -->
		<script src="assets/js/plugins/nicescroll/jquery.nicescroll.min.js"></script>
		<!-- Bootstrap -->
		<script src="assets/js/bootstrap.min.js"></script>

		<!--[if lte IE 9]>
			<script src="assets/js/plugins/placeholder/jquery.placeholder.min.js"></script>
			<script>
				$(document).ready(function() {
					$('input, textarea').placeholder();
				});
			</script>
		<![endif]-->
		
		<!-- Favicon -->
		<link rel="shortcut icon" href="assets/img/favicon.ico" />
		<!-- Apple devices Homescreen icon -->
		<link rel="apple-touch-icon-precomposed" href="assets/img/apple-touch-icon-precomposed.png" />


		<style type="text/css">
			#footer {
				position: fixed;
				width: 100%;
				bottom: 0;
			}
			body { background:  url("assets/img/bg.png") !important; } /* Adding !important forces the browser to overwrite the default style applied by Bootstrap */
		</style>

		<!-- FOR UPLOAD BAR -->
		<style>
			.progress { position:relative; width:300px; border: 1px solid #FF7800; padding: 1px; border-radius: 3px; }
			.bar { width:0%; height:20px; border-radius: 3px; }
			.percent { position:absolute; display:inline-block; top:2px; left:48%; }
		</style>

	</head>
	<body class='error'>						

		<div class="container-fluid" id="content">
			<div class="wrapper">
				<div class="code" align="center">
					<img src="assets/img/logo.png" alt="" class='retina-ready' width="420">
					<div class="desc" align="left">
					<p style="font-size:1.0em">
						Chúng tôi sẽ liên tục tự động kiểm tra hoạt động của trang web của bạn. Trong trường hợp Website của bạn có những dấu hiệu bất thường như bị tấn công ngừng hoạt động hoặc bị hack... chúng tôi sẽ thông báo ngay lập tức cho bạn qua email !
					</p>
				</div>
				</div>			
				<div class="login-body">					
					<form action="" method='POST' class='form-validate' id="test">
						<div class="control-group">
							<div class="pw controls">
								<input type="text" name="uname" placeholder="Your name" class='input-block-level' data-rule-required="true" required>
							</div>
						</div>
						<div class="control-group">
							<div class="email controls">
								<input name='uemail' type='email' placeholder="Email address" class='input-block-level' data-rule-required="true" data-rule-email="true" required>
							</div>
						</div>
						<div class="control-group">
							<div class="pw controls">
								<input name="uwebsite" type='url' placeholder="Your Website" class='input-block-level' data-rule-required="true" required>
							</div>
						</div>						
						<div class="submit">							
							<input type="submit" value="ĐĂNG KÝ" class='btn btn-primary'>
						</div>
            </br>
            <?php
            // For DEBUG purpose
            ini_set('display_errors',1); 
            error_reporting(E_ALL);
            ////////////////////////////
              if (isset($_POST['uwebsite']) && isset($_POST['uemail']) && isset($_POST['uname'])){
                include("connectdb.php");
                $con = ConnectDB() or die("can't connect to DB");
                $uwebsite = mysqli_real_escape_string($con, $_POST['uwebsite']);
                $uemail = mysqli_real_escape_string($con, $_POST['uemail']);
                $uname = mysqli_real_escape_string($con, $_POST['uname']);
                //
                // Se co truong hop 1 site nhung nhieu thang cung quan tri ma dai ca :D
                //
                //$checkExistingWebsite = mysqli_query($con,"SELECT * FROM webChecker WHERE uwebsite='$uwebsite'") or die(mysqli_error($con));
                //$status = mysqli_fetch_row($checkExistingWebsite);
                // var_dump($status);
                //if ($status == null){
                mysqli_query($con,"INSERT INTO webChecker (uwebsite, uemail, uname, ulang, ustatus) VALUES ('$uwebsite', '$uemail', '$uname', 'vi', 'up')") or die(mysqli_error($con));
                echo '<div class="alert alert-warning col-md-4" role="alert">Cảm ơn ' . $uname . ' đã sử dụng dịch vụ !</div>';  
                //}else{
                //  echo '<div class="alert alert-warning col-md-4" role="alert">Website already being in checking status!</div>';  
                //}
              }
            ?>
					</form>					
				</div>
			</div>
		</div>
		<div id="footer">			
			<div class="container">
			<p>Powered by Guru Team<span class="font-grey-4">|</span> <a href="register.php"><b>Đăng ký kiểm tra trạng thái website </b></a><span class="font-grey-4">|</span> <a href="contact.php">Contact</a> <span class="font-grey-4">|</span> <a href="donate">Donate</a> 
			</p>
			</div>
			<a href="#" class="gototop"><i class="icon-arrow-up"></i></a>
		</div>
	</body>
</html>