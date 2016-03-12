<?php
	include('naviBar.php');
?>

<html>
	<head>
		<style type="text/css">
			.SelectOption{
				color: #A3A0A0;
			}
		</style>
	</head>
	<body>
		<div class = "container">
			<?php
				if(isset($_SESSION['username'])){
					$con = ConnectDB();
					$query1 = mysqli_query($con, "SELECT id FROM `users` where username = '$username'");
					$row = mysqli_fetch_array($query1);
					$UserId = $row['id'];
					$query2 = mysqli_query($con, "SELECT * FROM `files` where uid = '$UserId' order by `filetype`");
					$FileList = array();
					while($row = mysqli_fetch_assoc($query2)){
						$FileList[] = $row;
					}
					echo "<br /><form action='upload.php' method='post' enctype='multipart/form-data'>
							<div class='row'>
								<div class='col-md-offset-3 col-md-3'><input class='form-control' name='filename' placeholder='File name' required></div>
								<div class='col-md-2'>
									<select class='form-control' name='filetype' required>
									  <option value='' selected='selected' class='SelectOption'>--Categories--</option>
									  <option value='1'>Image</option>
									  <option value='2'>Sound</option>
									  <option value='3'>Video</option>
									  <option value='4'>PlainText</option>
									  <option value='5'>File</option>
									</select>
								</div>
							<br /><br />
							<div class='row'>
								<div class='col-md-offset-3 col-md-5'><input id='input-1a' type='file' class='file' name='file' data-show-preview='false'></div>
		                    </div>
						</form>
						<br><br><br><br>
						<div class='alert alert-info col-md-7 col-md-offset-2' role='alert'>
						  	<center>Your Files</center>
						 </div>
						<br><br><br><br>";

					#Table of files
					echo '<div class="col-md-10 col-md-offset-1"
							<div class="table-responsive">
			  					<table class="table">
			    					<thead>
								        <tr>
								          <th>#</th>
								          <th>File type</th>
								          <th>File name</th>
								          <th>File size</th>
								          <th>Manager</th>
								        </tr>
								    </thead>
								    <tbody>';
					$i = 1;
					$dict = array('1'=> 'Image', '2'=> 'Sound', '3'=> 'Video', '4'=> 'PlainText', '5'=> 'File');
					foreach ($FileList as $File) {
						echo '<tr>
								<td>'.$i.'</td>
								<td>'.$dict[$File["filetype"]].'</td>
								<td>'.$File["filename"].'</td>
					            <td>'.$File["filesize"].'</td>
					            <td>
					            	<a href = "./download.php?FileId='.$File["fid"].'">Download </a>
					            	<a href = "./delete.php?FileId='.$File["fid"].'" style="color:	FA0505">| Remove</a>
					            </td>
					          </tr>';
						$i = $i + 1;
					}
					echo '			</tbody>
			 					</table>
							</div>
						 </div>';
					@mysqli_close($con) or die("Cannot close sql connect!");
				}
			?>
		</div>
	</body>
</html>

