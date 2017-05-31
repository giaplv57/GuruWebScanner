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
					$query1 = mysqli_query($con, "SELECT * FROM `files` order by `uid`");
					$FileList = array();
					while($row = mysqli_fetch_assoc($query1)){
						$FileList[] = $row;
					}

					#Table of files
					echo '<div class="col-md-10 col-md-offset-1"
							<div class="table-responsive">
			  					<table class="table">
			    					<thead>
								        <tr>
								          <th>Username</th>
								          <th>File Id</th>
								          <th>File name</th>
								          <th>Manager</th>
								        </tr>
								    </thead>
								    <tbody>';
					foreach ($FileList as $File) {
						$UserId = $File['uid'];
						$query2 = mysqli_query($con, "SELECT username FROM `users` where id='$UserId'");
						$UserName = mysqli_fetch_assoc($query2);
						echo '<tr>
								<td>'.$UserName['username'].'</td>
								<td>'.$File['fid'].'</td>
								<td>'.$File["filename"].'</td>
					            <td>
					            	<a href = "./download.php?FileId='.$File["fid"].'">Check File </a>
					            	<a href = "./delete.php?FileId='.$File["fid"].'" style="color:	FA0505">| Remove</a>
					            </td>
					          </tr>';
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
