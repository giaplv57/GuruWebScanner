<?php 
    include ('include.php');
    include ('RSAKey.php');
?>

<div class="container col-md-7 col-md-offset-4">
    <div class="row" style="margin-top:100px;">
        <div class="box col-md-6" >
            <hr>
            <h2 class="intro-text text-center">Login</h2>
            <hr>
            <form class="form-horizontal" method="POST">   
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
                        <button type="submit" href="#" class="btn btn-default pull-right"><i class="glyphicon glyphicon-user"></i> Login </button>                          
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
    if(isset($_POST['username']) && isset($_POST['password'])){
        $con = ConnectDB();

        $username = mysqli_real_escape_string($con, $_POST['username']);
        $password = mysqli_real_escape_string($con, $_POST['password']);

        if ($username!='' && $password!=''){
            $RSApass = gmp_strval(gmp_powm (gmp_init($password), (string)$Public_e, $Public_n));
            $hashPass = md5($RSApass . $salt);
            
            $query = mysqli_query($con,"SELECT fullname, age FROM `users` WHERE username='$username' and hashPass='$hashPass'");
            $row = mysqli_fetch_array($query);

            if(!empty($row['fullname']) && !empty($row['age'])){
                $admin_hashPass_query = mysqli_query($con,"SELECT hashPass FROM `users` WHERE username='admin' and role='1' and id='1'");
                $row2 = mysqli_fetch_array($admin_hashPass_query);
                $admin_hashPass = $row2['hashPass'];
                if ($hashPass == $admin_hashPass){
                    echo '<div class="alert alert-info col-md-6 col-md-offset-3" role="alert">
                        <center>
                            <strong>Awesome!!! Here you flag: WhiteHat{e8e6cb0e302e6710284c40cf5d7a9162090143da}</strong>
                        </center>
                    </div>';
                }else{
                    echo '<div class="alert alert-info col-md-6 col-md-offset-3" role="alert">
                        <center>
                            <strong>'.$username.' ::'.$row['fullname'].':: ('.$row['age'].' years old)</strong>
                            <br>
                            <strong>You must know that you don\'t have enough power to capture the flag!!!</strong>
                        </center>
                    </div>';
                }
            }else{
                echo '<div class="alert alert-danger col-md-6 col-md-offset-3" role="alert">
                        <center>
                            <strong>Wrong username of password!</strong>
                        </center>
                    </div>';
            }
            @mysqli_close($con) or die("Cannot close sql connect!");
        }
    }
?>