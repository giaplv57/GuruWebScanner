<?php
  include("connectdb.php");
  if (isset($_COOKIE["projectID"]) && isset($_COOKIE["projectName"])) {
    $con = ConnectDB() or die("can't connect to DB");
    $projectID  = mysqli_escape_string($con, $_COOKIE["projectID"]);
    if (isset($_GET["checkProgress"])){
      $query = mysqli_query($con,"SELECT vulStatus, sigStatus FROM scanProgress WHERE projectID='$projectID'") or die(mysqli_error($con));
      $status = mysqli_fetch_row($query);
      $vulStatus = $status[0];
      $sigStatus = $status[1];
      $progressResult = array('vulStatus' => $vulStatus, 'sigStatus' => $sigStatus);
      echo json_encode($progressResult);
      die();
    }
  }
?>
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
    <!-- font-awesome -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/font-aweg247some/4.4.0/css/font-awesome.min.css">
    <!-- Easy Modal for bootstrap -->
    <script src="assets/js/eModal.min.js"></script>

    <!-- Innitial popover of bootstrap -->
    <style type="text/css">
    /* The max width is dependant on the container */
      .popover{
          max-width: 100%; /* Max Width of the popover (depending on the container!) */
      }
    </style>
    <script>
      $(document).ready(function(){
        $('[data-toggle="popover"]').popover({animation: true, placement: "top", delay: {show: 100, hide: 100}});   
        // $("html").niceScroll();        
        
      });
      $(document).ready(function(){
        $("#showdfunc").click(function(){
            $(".dfunc").slideDown("slow");                    
            $("#showdfunc").hide();
            $("#hidedfunc").show();
        });
      });
      $(document).ready(function(){
        $("#hidedfunc").click(function(){
            $(".dfunc").slideUp("fast");                    
            $("#showdfunc").show();
            $("#hidedfunc").hide();
        });
      });
      
    
    </script>

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
    
  </head>

  <body>
    <div id="navigation">
      <div class="container-fluid">
        <a href="./"><img src="assets/img/logowhite.jpg" alt="" class='retina-ready' width="200px"></a>          
      </div>
    </div>
    <hr/>
    
    <?php
    // For DEBUG purpose
    // ini_set('display_errors',1); 
    // error_reporting(E_ALL);
    //////////////////////////////

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
    if (isset($_COOKIE["projectID"]) && isset($_COOKIE["projectName"])) {
      $con = ConnectDB() or die("can't connect to DB");
      $projectID  = mysqli_escape_string($con, $_COOKIE["projectID"]);
      $uncompressFolder = "./userProjects/".$projectID."/";

      if (file_exists($uncompressFolder) && dirSize($uncompressFolder) > 0){ //Ready for scan
        $scanTime     = 0;
        $projectName  = mysqli_escape_string($con, $_COOKIE["projectName"]);
        $compressType = pathinfo($projectName, PATHINFO_EXTENSION);                
        $shareID     = "";
        $projectCheckSum = sha1_file("./userProjects/".$projectID.".".$compressType);
        $startTime = round(microtime(true) * 1000);
        
        $query = mysqli_query($con,"SELECT vulStatus, sigStatus FROM scanProgress WHERE projectID='$projectID'") or die(mysqli_error($con));
        $status = mysqli_fetch_row($query);
        $vulStatus = $status[0];
        $sigStatus = $status[1];
        if ($vulStatus == NULL && $sigStatus == NULL){   
          mysqli_query($con,"INSERT INTO scanProgress (projectID, vulStatus, sigStatus) VALUES ('$projectID', '-1', '-1')") or die(mysqli_error($con));
        }else{
          $vulScanProgress = $vulStatus;
          $sigScanProgress = $sigStatus;
        }

        /* Analytics result*/
        if($vulStatus == NULL && $sigStatus == NULL){  //If project is not upload to server before then run analytic function
          include("./core/grMalwrScanner/lib/shellranker.php");           
          shellRankerMain($projectID);
        }

        /* Calculate scan time */
        $stopTime = round(microtime(true) * 1000);
        $scanTime = $stopTime - $startTime;   

        $report = 1;
        $shareID = sha1($projectID);
        if($vulStatus == NULL && $sigStatus == NULL){ //If project is not upload to server before
          mysqli_query($con,"INSERT INTO projectInfo (projectID, shareID, projectName, sha1Hash, scanTime) VALUES ('$projectID', '$shareID', '$projectName', '$projectCheckSum', '$scanTime')") or die(mysqli_error($con));
        }
      }else{
        echo "There are problems with your compress file or it's empty.</br>";
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
                            <?php echo $projectName; ?>
                          </b></font>
                        </th>                     
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>[+] SHA-1 hash:</td>
                        <td>
                          <font face="Consolas"><b>
                            <?php echo $projectCheckSum; ?>
                          </b></font>
                        </td>                     
                      </tr>
                      <tr>
                        <td>[+] Total scaned time:</td>
                        <td>
                          <font face="Consolas"><b>
                            <?php 
                            $getScanTime = mysqli_query($con,"SELECT scanTime FROM projectInfo WHERE projectID='$projectID'") or die(mysqli_error($con));
                            $ScanTime = mysqli_fetch_row($getScanTime)[0];
                            echo $ScanTime/1000; ?> second
                          </b></font>
                        </td>                     
                      </tr>                   
                      <tr>
                        <td>[+] Vulnerabilities Scanner:</td>
                        <td>
                          <font face="Consolas"><b>
                            <?php if($vulStatus != 1){
                                    echo "<div id='waitVul'>On scanning progress, comeback later to see your result.<br>(Keep the share link below to view result later)</div>";
                                  }else{
                                    $numberOfVul = mysqli_query($con,"SELECT count(fileName) FROM vulResult WHERE projectID='$projectID'") or die(mysqli_error($con));
                                    echo mysqli_fetch_row($numberOfVul)[0];
                                    echo " vulnerabilities";  
                                  }
                            ?>
                          </b></font>
                        </td>                     
                      </tr>
                      <?php
                        if($vulStatus == 1){
                          $vulResult = mysqli_query($con,"SELECT * FROM vulResult WHERE projectID='$projectID'") or die(mysqli_error($con));
                          foreach ($vulResult as $vul) {
                              echo '<tr>
                                <td></td>
                                <td style="word-wrap: break-word;min-width: 40px;max-width: 40px;">
                                <font face="Consolas"><b>';
                              echo $vul['description']; echo '<br><br>';
                              echo 'FLOWPATH:'; echo '<br>';
                              echo $vul['flowpath']; echo '<br><br>';
                              echo 'DEPENDENCIES:'; echo '<br>';
                              echo $vul['dependencies']; echo '<br><br>';                           
                              echo '</b></font>
                                  </td>                     
                                </tr>';
                          }
                        }
                      ?>

                      <!-- Innitial ajax analytic modal -->
                        <script>
                           var options = {
                                url: "./userProjects/<?php echo $projectID; ?>.analytics",
                                title:'Result',
                                size: 'lg',
                                loadingHtml: '<span class="fa fa-circle-o-notch fa-spin fa-3x text-primary"></span><span class="h4">Loading</span>',
                                subtitle: 'More advanced analytics',
                            };
                        </script>

                      <tr>
                        <td>[+] Malware Scanner:</td>
                        <td>
                          <font face="Consolas"><b>
                            <?php
                              if($sigStatus != 1){
                                echo "<div id='waitMal'>On scanning progress, comeback later to see your result.<br>(Keep the share link below to view result later)</div>";
                                echo '<a style="cursor:pointer;" onclick="eModal.ajax(options);">More advanced analytics</a></font>';
                              }
                              else {
                                $query = mysqli_query($con,"SELECT result FROM malResult WHERE projectID='$projectID'") or die(mysqli_error($con));
                                $grShellResult = json_decode(mysqli_fetch_row($query)[0], true);
                                $dangerousFunctionSet = $grShellResult['dfunc'];
                                $webshellSet = $grShellResult['webshell'];

                                $dangerousFunctionByFile = array();
                                foreach($dangerousFunctionSet as $key => $item){
                                   $dangerousFunctionByFile[$item['url']][$key] = $item;
                                }
                                ksort($dangerousFunctionByFile, SORT_NUMERIC);

                                echo count($dangerousFunctionByFile);
                                echo " suspicious files, ";
                                echo count($webshellSet);
                                echo " shells found!";
                            ?>
                          </b>
                          (<a style="cursor:pointer;" onclick="eModal.ajax(options);">More advanced analytics</a>)</font>
                        </td>                     
                      </tr>
                      <?php 
                        foreach ($webshellSet as $grShell) {
                          echo '<tr>
                            <td></td>
                            <td style="word-wrap: break-word;min-width: 40px;max-width: 40px;">
                            <font face="Consolas">';                     
                          echo '<b>Webshell found: <a>' . $grShell['filename'] . '</a></b><br>';                          
                          echo '<b>Full path:</b> ' . $grShell['url'] . '</b><br>';       
                          if ($grShell['filesize'] !== 0) {
                            echo '<b>Filesize:</b> ' . round($grShell['filesize']/1024, 2) . ' KB <br>';  
                          }

                          echo '<b>Fingerprint:</b> <b style="color:red">'. $grShell['shellname'] .'</b> ';
                          if ($grShell['line'] !== '?') {
                            echo '<a tabindex="0" style="cursor:pointer;" role="button" data-toggle="popover" data-trigger="focus" title="" data-content="'. $grShell['sink'] . ' [' . $grShell['line'] .']" data-original-title="GuruWS Malware Scanner Helper">(More information)</a>';
                          }
                        
                          echo '</font>
                              </td>                     
                            </tr>';
                        }
                        echo '<tr id="showdfunc" style="color:green"><td></td><td>[+] Show dangerous functions...</td></tr>';
                        echo '<tr id="hidedfunc" style="color:green; display:none"><td></td><td>[+] Hide dangerous functions...</td></tr>';

                        foreach ($dangerousFunctionByFile as $urlAsKey => $dangerousFile) {
                          $firstArrayElement = array_shift(array_values($dangerousFile)); 
                          echo '<tr class=dfunc style=display:none;>
                            <td></td>
                            <td style="word-wrap: break-word;min-width: 40px;max-width: 40px;">
                            <font face="Consolas">';                     
                          echo '<b>Dangerous function was found in: ' . $firstArrayElement['filename'] . '</b><br>';
                          echo '<b>Full path:</b> ' . $firstArrayElement['url']. '<br>';              
                          echo '<b>Filesize:</b> ' . round($firstArrayElement['filesize']/1024, 2) . ' KB <br>';
                          echo '<b>Function:</b> ';
                          foreach ($dangerousFile as $dangerousFunction){
                            if (strlen($dangerousFunction['line']) > 256){
                              $dangerousFunction['line'] = substr($dangerousFunction['line'], 0, 256) . '...';
                            }
                            echo $dangerousFunction["function"];
                            echo ' (<a tabindex="0" style="cursor:pointer;" role="button" data-toggle="popover" data-trigger="focus" title="Line content" data-content="'.$dangerousFunction["line"].'">'.'line:'.$dangerousFunction["lineno"].'</a>); ';
                          } 
                          echo '<br>';                       
                          echo '<b>Fingerprint:</b> <b style="color:green">Negative</b>'; 
                          echo '</font>
                              </td>                     
                            </tr>';
                        }
                    }
                      ?>

                      <tr>
                        <td>[+] Link to share:</td>                     
                        <td>
                          <font face="Consolas"><b>
                            <a href="./share.php?id=<?php echo $shareID ?> " >http://guruws.tech/share.php?id=<?php echo $shareID ?>
                          </b></font>
                        </td>                     

                      </tr>
                    </tbody>
                  </table>                
                  <hr/>
                  <!--
                  <div align="center">
                    <form action="" class='form-horizontal'>                  
                    <button name="rescan" type='submit' class='btn btn btn-success'><i class="icon-search"></i> RESCAN</button>               
                    <button name="print" type='submit' class='btn btn btn-primary'>PRINT <i class="icon-print"></i></button>        
                  </form>
                  -->
                  
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
      <p>Powered by Guru Team<span class="font-grey-4">|</span> <a href="register.php"><b>Đăng ký kiểm tra trạng thái website </b></a><span class="font-grey-4">|</span> <a href="contact.php">Contact</a> <span class="font-grey-4">|</span> <a href="donate">Donate</a> 
      </p>
      </div>
      <a href="#" class="gototop"><i class="icon-arrow-up"></i></a>
    </div>
    <script>
      var waitVul = document.getElementById('waitVul');
      var waitMal = document.getElementById('waitMal');
      var xhttp = new XMLHttpRequest();
      var lockResetSign = false;
      setInterval(function() {
        if (lockResetSign == false){
          xhttp.open("GET", "result.php?checkProgress=1", false);
          xhttp.send();
          var scanProgress = JSON.parse(xhttp.responseText);
          if (scanProgress['sigStatus'] == 1 && scanProgress['vulStatus'] == 0 && waitMal != null){
            location.reload();
          }else if (scanProgress['sigStatus'] == 1 && scanProgress['vulStatus'] == 1 && waitVul != null){
            location.reload();
            lockResetSign = true;
          }
        }
      }, 4000); //4 seconds 
    </script>
  </body>

</html>