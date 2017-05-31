<?php
	include('naviBar.php');
?>

<html>
	<body>
		<div class = "container">
			<?php
				if(isset($_SESSION['username']) and $_SESSION['role']==='1'){
					$con = ConnectDB();
					$query1 = mysqli_query($con, "SELECT * FROM `users`");
					$UserList = array();
					while($row = mysqli_fetch_assoc($query1)){
						$UserList[] = $row;
					}

					#Table of users
					echo '<div class="col-md-10 col-md-offset-1"
							<div class="table-responsive">
			  					<table class="table">
			    					<thead>
								        <tr>
								          <th>#</th>
								          <th>Role</th>
								          <th>Username</th>
								          <th>Lastname</th>
								          <th>Email</th>
								          <th>Status</th>
								        </tr>
								    </thead>
								    <tbody>';

					foreach ($UserList as $User) {
						$manage = '';
						$role = '';
						if ($User['status']==='1'){
							$manage = '<a href = "./userprocess.php?uid='.$User['id'].'&action=block">Active</a>';
						}else{
							$manage = '<a href = "./userprocess.php?uid='.$User['id'].'&action=active" style="color:FA0505">Block</a>';
						}
						if ($User['role']==='0'){
							$role = '<a href = "./userprocess.php?uid='.$User['id'].'&action=toadmin">Member</a>';
						}else{
							$role = '<a href = "./userprocess.php?uid='.$User['id'].'&action=tomember" style="color:E105FA">Admin</a>';
						}

						echo '<tr>
								<td>'.$User['id'].'</td>
								<td>'.$role.'</td>
								<td>'.$User['username'].'</td>
								<td>'.$User['lastName'].'</td>
								<td>'.$User['email'].'</td>
					            <td>'.$manage.'</td>
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

