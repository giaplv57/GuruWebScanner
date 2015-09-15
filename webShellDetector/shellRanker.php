<?php
	# Smallest filesize to checkfor in bytes.  
	define("SMALLEST", 60);
    $GLOBALS['rank_list'] = array();

	//For DEBUG purpose
	ini_set('display_errors',1); 
	error_reporting(E_ALL);
    //////////////////////////////////

	class LanguageIC{
		var $char_count = array();
		var $total_char_count = 0;
		var $results = array();
		var $ic_total_results = "";
		
		function __construct(){
			for($x = 0; $x < 256; $x++){
				$this->char_count[chr($x)] = 0;
			}
		}

		function calculate_char_count($data){
			// """Method to calculate character counts for a particular data file."""
			if (!$data){
				return 0;
			}
			for($x = 0; $x < 256; $x++){
			   $char = chr($x);
			   $charcount = substr_count($data, $char);
			   $this->char_count[$char] += $charcount;
			   $this->total_char_count += $charcount;
			}
		}
		function calculate_IC(){
			// """Calculate the Index of Coincidence for the self variables"""
			$total = 0;
			foreach($this->char_count as $key => $val){
				if ($val == 0){
			    	continue;
			   	}
			   	$total += $val * ($val-1);
			}
			try{
			   	$ic_total = $total/($this->total_char_count * ($this->total_char_count - 1));
			}catch (Exception $e){
			   	$ic_total = 0;
			}
			$this->ic_total_results = $ic_total;
		}

		function calculate($filename,$data){
			// """Calculate the Index of Coincidence for a file and append to self.ic_results array"""
			if (!$data){
			   return 0;
			}
			$char_count = 0;
			$total_char_count = 0;

			for($x = 0; $x < 256; $x++){
				$char = chr($x);
			   	$charcount = substr_count($data, $char);
			   	$char_count += $charcount * ($charcount - 1);
			   	$total_char_count += $charcount;
			}
			$ic = $char_count/($total_char_count * ($total_char_count - 1));
			$this->results[$filename] = $ic;
			# Call method to calculate_char_count and append to total_char_count
			$this->calculate_char_count($data);
			return $ic;
		}

		function sort(){
			asort($this->results);
			$this->calculate_IC();
            resultsAddRank($this->results);
		}
	}
	class Entropy{
		var $results = array();

		function calculate($filename, $data){
			if (!$data) {
          		return 0;
			}
			$entropy = 0;
	       	$stripped_data = str_replace(' ', '', $data);
	       	for($x = 0; $x < 256; $x++){
	        	$p_x = substr_count($stripped_data, chr($x))/strlen($stripped_data);
	        	// $p_x = float($stripped_data.count(chr(x)))/strlen($stripped_data);
	           	if ($p_x > 0){
	               	$entropy += - $p_x * log($p_x, 2);
	           	}
	        }
	       	// self.results.append({"filename":filename, "value":entropy})
	       	$this->results[$filename] = $entropy;
	       	// $this->results[] = $entropy;
	       	// return $entropy;
		}
		function sort(){
			arsort($this->results);
            resultsAddRank($this->results);
		}
	}
	class LongestWord{
		// """Class that determines the longest word for a particular file."""
		var $results = array();

		function calculate($filename, $data){
			// """Find the longest word in a string and append to longestword_results array"""
			if (!$data){
			   return 0;
			}
			$longest = 0;
			$longest_word = "";
			$words =  preg_split( '/\s|\n|\r|\,/', $data);
			if ($words){
			   	foreach ($words as $word) {
			       	$length = strlen($word);
			       	if ($length > $longest){
			           	$longest = $length;
			           	$longest_word = $word;
			       	}
			    }
			}
			$this->results[$filename] = $longest;
			return $longest;
		}

		function sort(){
			arsort($this->results);
            resultsAddRank($this->results);
		}
	}
	class SignatureNasty{
		// """Generator that searches a given file for nasty expressions"""
		var $results = array();

		function calculate($filename, $data){
			if(!$data){
				return "";
			}
			$matches = array();
			preg_match_all('/(eval\(|file_put_contents|base64_decode|python_eval|exec\(|passthru|popen|proc_open|pcntl|assert\(|system\(|shell)/i', $data, $matches, PREG_SET_ORDER);	//The PREG_SET_ORDER flag to ensure result appropriately distribute to array
			$this->results[$filename] = count($matches);	
		}

		function sort(){
			arsort($this->results);
            resultsAddRank($this->results);
		}
	}
	class SignatureSuperNasty{
		var $results = array();

		function calculate($filename, $data){
			if(!$data){
				return "";
			}
			$matches = array();
			preg_match_all('/(@\$_\[\]=|\$_=@\$_GET|\$_\[\+""\]=)/i', $data, $matches, PREG_SET_ORDER);	//The PREG_SET_ORDER flag to ensure result appropriately distribute to array , i flag to perform case-insensitive
			$this->results[$filename] = count($matches);				
		}

		function sort(){
			arsort($this->results);
            resultsAddRank($this->results);
		}
	}
	class UsesEval{
	   // """Generator that searches a given file for nasty eval with variable"""
		var $results = array();

		function calculate($filename, $data){
			if(!$data){
				return "";
			}
			$matches = array();
			preg_match_all('/(eval\(\$(\w|\d))/i', $data, $matches, PREG_SET_ORDER);	//The PREG_SET_ORDER flag to ensure result appropriately distribute to array , i flag to perform case-insensitive
			$this->results[$filename] = count($matches);				
		}

		function sort(){
			arsort($this->results);
		}
	}
	class Compression{
		var $results = array();

		function calculate($filename, $data){
			if(!$data){
				return "";
			}
			$compressed = zlib_encode($data, 15);
			$ratio = strlen($compressed)/strlen($data);
			$this->results[$filename] = $ratio;
		}

		function sort(){
			arsort($this->results);
		}
	}

	function resultsAddRank($results){
        $rank = 1;
		$previousValue = false;
        $offset = 1;

        foreach ($results as $key=>$value){
            if ($previousValue and $previousValue != $value){
                $rank = $offset;
            }
            $GLOBALS['rank_list'][$key] += $rank;
            $previousValue = $value;
            $offset = $offset + 1;
        }
        return $GLOBALS['rank_list'];
	}

	function fileIterator ($path, $patern){
		$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path));
		$filter = new RegexIterator($iterator, '/(.*)\.(php|asp|aspx|scath|bash|zsh|csh|tsch|pl|py|txt|cgi|cfm)$/');
		$files = array(); 
		foreach ($filter as $file) {
		    if ($file->isDir() or filesize($file) < SMALLEST){ 
		        continue;
		    }
		    $files[] = $file->getPathname(); 
            $GLOBALS['rank_list'][$file->getPathname()] = 0;
		}
		return $files;
	}

	function shellRankerMain($newFilename){
		$path = "./userFiles/".$newFilename."/";
		$fileList = fileIterator($path, "");

		$EntropyTest = new Entropy();
		$LanguageICTest = new LanguageIC();
		$LongestWordTest = new LongestWord();
		$SignatureNastyTest = new SignatureNasty();
	    $SignatureSuperNastyTest = new SignatureSuperNasty();
	    // $UsesEvalTest = new UsesEval();
	    // $CompressionTest = new Compression();
	    
		foreach ($fileList as $filename){
			$data = file_get_contents($filename);
			$EntropyTest->calculate($filename, $data);
			$LanguageICTest->calculate($filename, $data);
			$LongestWordTest->calculate($filename, $data);
			$SignatureNastyTest->calculate($filename, $data);
	        $SignatureSuperNastyTest->calculate($filename, $data);
	        // $UsesEvalTest->calculate($filename, $data);
	        // $CompressionTest->calculate($filename, $data);
		}
		$EntropyTest->sort();
		$LanguageICTest->sort();
		$LongestWordTest->sort();
		$SignatureNastyTest->sort();
	    $SignatureSuperNastyTest->sort();
	    // $UsesEvalTest->sort();
	    // $CompressionTest->sort();
	    asort($GLOBALS['rank_list']);

	    $count = 10;
	    if(count($fileList) < $count){
	    	$count = count($fileList);
	    }

	    writeReportToFile($newFilename, $EntropyTest, $LanguageICTest, $LongestWordTest, $SignatureNastyTest, $SignatureSuperNastyTest, $GLOBALS['rank_list'], $count);
	    // $rankerResult = array('EntropyTest' => $EntropyTest, 'LanguageICTest' => $LanguageICTest, 'LongestWordTest' => 
	    // 		$LongestWordTest, 'SignatureNastyTest' => $SignatureNastyTest, 'SignatureSuperNastyTest' => $SignatureSuperNastyTest,
	    // 		'ranked_list' => $GLOBALS['rank_list'], 'listLength' => $count);

	    // return $rankerResult;
	}

	function writeReportToFile($newFilename, $EntropyTest, $LanguageICTest, $LongestWordTest, $SignatureNastyTest, $SignatureSuperNastyTest, $rankedList, $listLength){
		$path = "./userFiles/".$newFilename."/";
		$reportContent = '<div class="box box-color box-bordered">
							<font size="2px" face="Verdana">
							<div class="box-content nopadding">
								<table class="table table-hover table-nomargin">
									<thead>
										<tr>
											<th colspan=2>[+] Average IC for Search:</th>
										</tr>
									</thead>
									<tbody>
										<tr>
											<td>'.$LanguageICTest->ic_total_results.'</td>
											<td>
												<font face="Consolas"><b>
												</b></font>
											</td>											
										</tr>
										<tr>
											<th colspan=2>[+] Top '.$listLength.' lowest IC files:</th>
										</tr>';

		$temp = 0;
		foreach ($LanguageICTest->results as $key=>$value){
			if ($temp == $listLength) break;
			$reportContent = $reportContent.'<tr>
						<td class="">'.$value.'</td>
						<td class="">
							<font face="Consolas"><b>
								'.str_replace($path, "./", $key).'
							</b></font>
						</td>									
					</tr>';
			$temp++;
		}

		$reportContent= $reportContent.'<tr>
											<th colspan=2>[+] Top '.$listLength.' entropic files for a given search:</th>
										</tr>';

		$temp = 0;
		foreach ($EntropyTest->results as $key=>$value){
			if ($temp == $listLength) break;
			$reportContent = $reportContent.'<tr>
						<td class="">'.$value.'</td>
						<td class="">
							<font face="Consolas"><b>
								'.str_replace($path, "./", $key).'
							</b></font>
						</td>									
					</tr>';
			$temp++;
		}
		$reportContent = $reportContent.'<tr>
											<th colspan=2>[+] Top '.$listLength.' longest word files:</th>
										</tr>';
		$temp = 0;
		foreach ($LongestWordTest->results as $key=>$value){
			if ($temp == $listLength) break;
			$reportContent = $reportContent.'<tr>
						<td class="">'.$value.'</td>
						<td class="">
							<font face="Consolas"><b>
								'.str_replace($path, "./", $key).'
							</b></font>
						</td>									
					</tr>';
			$temp++;
		}

		$reportContent = $reportContent.'<tr>
											<th colspan=2>[+] Top '.$listLength.' signature match counts:</th>
										</tr>';
		$temp = 0;
		foreach ($SignatureNastyTest->results as $key=>$value){
			if ($temp == $listLength) break;
			$reportContent = $reportContent.'<tr>
						<td class="">'.$value.'</td>
						<td class="">
							<font face="Consolas"><b>
								'.str_replace($path, "./", $key).'
							</b></font>
						</td>									
					</tr>';
			$temp++;
		}
		$reportContent = $reportContent.'<tr>
											<th colspan=2>[+] Top '.$listLength.' SUPER-signature match counts (These are usually bad!):</th>
										</tr>';

		$temp = 0;
		foreach ($SignatureSuperNastyTest->results as $key=>$value){
			if ($temp == $listLength) break;
			$reportContent = $reportContent.'<tr>
						<td class="">'.$value.'</td>
						<td class="">
							<font face="Consolas"><b>
								'.str_replace($path, "./", $key).'
							</b></font>
						</td>									
					</tr>';
			$temp++;
		}
		$reportContent = $reportContent.'<tr>
											<th colspan=2>[+] Top cumulative ranked files:</th>											
										</tr>';
		$temp = 0;
		foreach ($rankedList as $key=>$value){
			if ($temp == $listLength) break;
			$reportContent = $reportContent.'<tr>
						<td class="">'.$value.'</td>
						<td class="">
							<font face="Consolas"><b>
								'.str_replace($path, "./", $key).'
							</b></font>
						</td>									
					</tr>';
			$temp++;
		}
		$reportContent = $reportContent.'</tbody>
										</table>
									</div>
									</font>
								</div>';

		$report = fopen("./userFiles/".$newFilename.".analytics","w");
		fwrite($report, $reportContent);
		fclose($report);
		// echo $reportContent;
	}

?>