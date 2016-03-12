<?php 
	include ('include.php');
	include ('RSAKey.php');
?>

<div class="container col-md-7 col-md-offset-4">
    <div class="row" style="margin-top:100px;">
	    <div class="box col-md-6" >
			<hr>
	        <h2 class="intro-text text-center">Create a new account</h2>
	        <hr>
	        <form class="form-horizontal" method="POST">   
	        	<div class="input-group" style="margin-bottom: 25px;">
	        		<span class="input-group-addon"><i class="glyphicon glyphicon-heart"></i></span>
	        		<input id="fullname" type="text" class="form-control" name="fullname" value="" placeholder="Fullname">                                        
	        	</div>

	        	<div class="input-group" style="margin-bottom: 25px;">
	        		<span class="input-group-addon"><i class="glyphicon glyphicon-education"></i></span>
	        		<input id="age" type="text" class="form-control" name="age" value="" placeholder="Age (number only)">                                        
	        	</div>

	        	<div class="input-group" style="margin-bottom: 25px;">
	        		<span class="input-group-addon"><i class="glyphicon glyphicon-user"></i></span>
	        		<input id="username" type="text" class="form-control" name="username" value="" placeholder="Username">                                        
	        	</div>

	        	<div class="input-group" style="margin-bottom: 25px;">
	        		<span class="input-group-addon"><i class="glyphicon glyphicon-lock"></i></span>
	        		<input id="password" type="password" class="form-control" name="password" placeholder="Personal Code (number only)">
	        	</div>                                                                  

	        	<div class="form-group">
	        		<!-- Button -->
	        		<div class="col-sm-12 controls">
	        			<button type="submit" href="#" class="btn btn-default pull-right"><i class="glyphicon glyphicon-user"></i> Sign Up </button>                          
	        		</div>
	        	</div>
	        </form>
	    </div>
	    <div class="box col-md-1">
	    	<div class="social-icons icon-circle icon-rotate">
                <center>
                    <a href="./home.php"><i class="fa fa-home fa-2x" style="color: rgba(0, 0, 0, 0.7); margin-left:-10px;"></i></a>
                </center>
            </div>
	    </div>
	</div>
</div>

<?php
	if(isset($_POST['username']) && isset($_POST['password']) && isset($_POST['fullname']) && isset($_POST['age'])){
		$con = ConnectDB();

		$fullname = mysql_real_escape_string($_POST['fullname']);
		$age = mysql_real_escape_string($_POST['age']);
		$username = mysql_real_escape_string($_POST['username']);
		$password = mysql_real_escape_string($_POST['password']);

		$RSApass = gmp_strval(gmp_powm (gmp_init($password), (string)$Public_e, $Public_n));
		$hashPass = md5($RSApass . $salt);

		if ($username!='' && $password!='' && $fullname!='' && $age!=''){
			$check = mysql_query("SELECT id FROM `users` WHERE username='$username'");
			if(mysql_num_rows($check) == 0){
			    $result = mysql_query("INSERT INTO users (username, fullname, age, RSApass, hashPass, role) VALUES ('$username', '$fullname', $age, '$RSApass', '$hashPass', '0')");
				$query = mysql_query("SELECT fullname FROM `users` WHERE username='$username'");
	            
	            if (mysql_num_rows($query) != 0){
		            while ($row = mysql_fetch_array($query)){
						echo '<div class="alert alert-success col-md-5 col-md-offset-3" role="alert">
								  	<center>
								  		<strong>Success!</strong>
								  	 	 \''.$username.'\' ('.$row['fullname'].')
								  	 	 <br>
								  	 	 You can now login to enjoy our service now!!!
								  	</center>
								  </div>';
					}
				}else{
					echo '<div class="alert alert-danger col-md-5 col-md-offset-3" role="alert">
							  		<center>
								  		<strong>Error!</strong>
								  		 Something wrong happened!!!.
							  		</center>
							  	</div>';
				}
			}else {
			    echo '<div class="alert alert-danger col-md-5 col-md-offset-3" role="alert">
					  		<center>
						  		<strong>Error!</strong>
						  		 Username already exists.
					  		</center>
					  	</div>';
			}
			@mysql_close($con) or die("Cannot close sql connect!");
		}
	}
?>
