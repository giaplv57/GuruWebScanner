<!doctype html>
<html>
<?php include("heading.php"); ?>

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
