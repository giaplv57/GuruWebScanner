<?php
	// add parsing error to output
	function add_error($message)
	{
		$GLOBALS['info'][] = $message;
	}
	
	// tokens to string for comments
	function tokens2string($tokens)
	{
		$output = '';
		for($i=0;$i<count($tokens);$i++)
		{
			$token = $tokens[$i];
			if (is_string($token))
			{	
				if($token === ',' || $token === ';')
					$output .= "$token ";
				else if(in_array($token, Tokens::$TOKEN_SPACEWRAP_C) || in_array($token, Tokens::$TOKEN_OPERATOR_C))
					$output .= " $token ";
				else	
					$output .= $token;
			}	
			else if(in_array($token[0], Tokens::$TOKEN_SPACEWRAP) || in_array($token[0], Tokens::$TOKEN_OPERATOR) || in_array($token[0], Tokens::$TOKEN_ASSIGNMENT))
				$output .= " {$token[1]} ";
			else
				$output .= $token[1];
		}
		return $output;
	}
	
	// prepare output to style with CSS
	function print_line_no($tokens=array(), $comment='', $line_nr, $title=false, $udftitle=false, $taintedVars=array())
	{
		$output = "linenr: ";
		$output .= $line_nr;
		return $output;
	}
	
	// detect vulnerability type given by the PVF name
	// note: same names are used in help.php!
	function get_vuln_node_title($func_name)
	{
		if(isset($GLOBALS['F_CONNECT'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_CONNECT']; }		
		else if(isset($GLOBALS['F_EXEC'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_EXEC'];  }
		else if(isset($GLOBALS['F_XSS'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_XSS'];  }
		else if(isset($GLOBALS['F_FILE_AFFECT'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_FILE_AFFECT']; }		
		else if(isset($GLOBALS['F_FILE_INCLUDE'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_FILE_INCLUDE'];  }		
		else if(isset($GLOBALS['F_CODE'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_CODE']; }
		else if(isset($GLOBALS['F_REFLECTION'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_REFLECTION']; }
		else if(isset($GLOBALS['F_XPATH'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_XPATH'];	 } 
		else if(isset($GLOBALS['F_LDAP'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_LDAP'];}
		else if(isset($GLOBALS['F_POP'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_POP'];  }
		else if(isset($GLOBALS['F_FILE_READ'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_FILE_READ'];  }			
		else if(isset($GLOBALS['F_HTTP_HEADER'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_HTTP_HEADER'];  }	
		else if(isset($GLOBALS['F_SESSION_FIXATION'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_SESSION_FIXATION'];  }
		else if(isset($GLOBALS['F_DATABASE'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_DATABASE'];  }					
		else if(isset($GLOBALS['F_OTHER'][$func_name])) 
		{	$vulnname = $GLOBALS['NAME_OTHER']; } // :X			 			
		else 
			$vulnname = "unknown vuln name";
		return $vulnname;	
	}
	
	// detect vulnerability type given by the PVF name
	// note: same names are used in help.php!
	function inc_vuln_counter($func_name)
	{
		if(isset($GLOBALS['F_XSS'][$func_name])) 
		{	$GLOBALS['count_xss']++; }	
		else if(isset($GLOBALS['F_HTTP_HEADER'][$func_name])) 
		{	$GLOBALS['count_header']++; }
		else if(isset($GLOBALS['F_SESSION_FIXATION'][$func_name])) 
		{	$GLOBALS['count_sf']++; }
		else if(isset($GLOBALS['F_DATABASE'][$func_name])) 
		{	$GLOBALS['count_sqli']++; }	
		else if(isset($GLOBALS['F_FILE_READ'][$func_name])) 
		{	$GLOBALS['count_fr']++; }
		else if(isset($GLOBALS['F_FILE_AFFECT'][$func_name])) 
		{	$GLOBALS['count_fa']++; }		
		else if(isset($GLOBALS['F_FILE_INCLUDE'][$func_name])) 
		{	$GLOBALS['count_fi']++; }	
		else if(isset($GLOBALS['F_CONNECT'][$func_name])) 
		{	$GLOBALS['count_con']++; }
		else if(isset($GLOBALS['F_EXEC'][$func_name])) 
		{	$GLOBALS['count_exec']++; }
		else if(isset($GLOBALS['F_CODE'][$func_name])) 
		{	$GLOBALS['count_code']++; }
		else if(isset($GLOBALS['F_REFLECTION'][$func_name])) 
		{	$GLOBALS['count_ri']++; }
		else if(isset($GLOBALS['F_XPATH'][$func_name])) 
		{	$GLOBALS['count_xpath']++; } 
		else if(isset($GLOBALS['F_LDAP'][$func_name])) 
		{	$GLOBALS['count_ldap']++; }	
		else if(isset($GLOBALS['F_POP'][$func_name])) 
		{	$GLOBALS['count_pop']++; }
		else if(isset($GLOBALS['F_OTHER'][$func_name])) 
		{	$GLOBALS['count_other']++; } // :X
	}	
		
	// traced parameter output bottom-up
	/*
	function traverse_bottom_up($tree) 
	{
		echo '<ul';
		switch($tree->marker) 
		{
			case 1: echo ' class="userinput"'; break;
			case 2: echo ' class="validated"'; break;
			case 3: echo ' class="functioninput"'; break;
			case 4: echo ' class="persistent"'; break;
		}
		echo '><li>' . $tree->value;

		if($tree->children)
		{
			foreach ($tree->children as $child) 
			{
				traverse_bottom_up($child);
			}
		}
		echo '</li></ul>',"\n";
	}
	*/
	
	// traced parameter output top-down
	/*
	function traverse_top_down($tree, $start=true, $lines=array()) 
	{

		foreach ($tree->children as $child) 
		{
			$lines = traverse_top_down($child, false, $lines);
		}
		
		// do not display a line twice
		// problem: different lines in different files with equal line number
		if(!isset($lines[$tree->line]))
		{	
			// add to array to ignore next time
			$lines[$tree->line] = 1;
		}	
		
		return $lines;
	}
	*/	

	// requirements output
	/*
	function dependencies_traverse($tree) 
	{
		if(!empty($tree->dependencies))
		{			

			foreach ($tree->dependencies as $linenr=>$dependency) 
			{
				if(!empty($dependency))
				{
					echo print_line_no($dependency, '', $linenr);
				}
			}
		}
	}
	*/
	/*
	// check for vulns found in file
	function file_has_vulns($blocks)
	{
		foreach($blocks as $block)
		{
			if ($block->vuln)
				return true;
		}
		return false;
	}
	*/	
	
	/*
	// print the scanresult
	function printoutput($output, $treestyle=1)
	{

		if (!empty($output))
		{
			$nr=0;
			reset($output);
			do
			{				
				if(key($output) != "" && !empty($output[key($output)]) && file_has_vulns($output[key($output)]))
				{		
					echo '<div class="filebox">',
					'<span class="filename">File: ',key($output),'</span><br>',
					'<div id="',key($output),'"><br>';
	
					foreach($output[key($output)] as $vulnBlock)
					{	
						if($vulnBlock->vuln)	
						{
							$nr++;
							echo '<div class="vulnblock">',
							'<div id="pic',$vulnBlock->category,$nr,'" class="minusico" name="pic',$vulnBlock->category,'" style="margin-top:5px" title="minimize"',
							' onClick="hide(\'',$vulnBlock->category,$nr,'\')"></div><div class="vulnblocktitle">',$vulnBlock->category,'</div>',
							'</div><div name="allcats"><div class="vulnblock" style="border-top:0px" name="',$vulnBlock->category,'" id="',$vulnBlock->category,$nr,'">';
							
							if($treestyle == 2)
								krsort($vulnBlock->treenodes);
							
							foreach($vulnBlock->treenodes as $tree)
							{
								// we do not have a prescan yet so RIPS misses function calls before the actual declaration, so we output vulns in functions without function call too (could have happened earlier)
								// if(empty($tree->funcdepend) || $tree->foundcallee )
								{	
									echo '<div class="codebox"><table border=0>',"\n",
									'<tr><td valign="top" nowrap>',"\n",
									'<div class="fileico" title="review code" ',
									'onClick="openCodeViewer(this,\'',
									addslashes($tree->filename), '\',\'',
									implode(',', $tree->lines), '\');"></div>'."\n",
									'<div id="pic',key($output),$tree->lines[0],'" class="minusico" title="minimize"',
									' onClick="hide(\'',addslashes(key($output)),$tree->lines[0],'\')"></div><br />',"\n";

									if(isset($GLOBALS['scan_functions'][$tree->name]))
									{
										// help button
										echo '<div class="help" title="get help" onClick="openHelp(this,\'',
										$vulnBlock->category,'\',\'',$tree->name,'\',\'',
										(int)!empty($tree->get),'\',\'',
										(int)!empty($tree->post),'\',\'',
										(int)!empty($tree->cookie),'\',\'',
										(int)!empty($tree->files),'\',\'',
										(int)!empty($tree->cookie),'\')"></div>',"\n";
										
										if(isset($GLOBALS['F_DATABASE'][$tree->name])
										|| isset($GLOBALS['F_FILE_AFFECT'][$tree->name]) 
										|| isset($GLOBALS['F_FILE_READ'][$tree->name]) 
										|| isset($GLOBALS['F_LDAP'][$tree->name])
										|| isset($GLOBALS['F_XPATH'][$tree->name])
										|| isset($GLOBALS['F_POP'][$tree->name]) )
										{
											// data leak scan
											if(!empty($vulnBlock->dataleakvar))
											{
												echo '<div class="dataleak" title="check data leak" onClick="leakScan(this,\'',
												$vulnBlock->dataleakvar[1],'\',\'', // varname
												$vulnBlock->dataleakvar[0],'\', false)"></div>',"\n"; // line
											} else
											{
												$tree->title .= ' (Blind exploitation)';
											}
										}	
									}
									
									if(!empty($tree->get) || !empty($tree->post) 
									|| !empty($tree->cookie) || !empty($tree->files)
									|| !empty($tree->server) )
									{										
										
										echo '<div class="exploit" title="generate exploit" ',
										'onClick="openExploitCreator(this, \'',
										addslashes($tree->filename),
										'\',\'',implode(',',array_unique($tree->get)),
										'\',\'',implode(',',array_unique($tree->post)),
										'\',\'',implode(',',array_unique($tree->cookie)),
										'\',\'',implode(',',array_unique($tree->files)),
										'\',\'',implode(',',array_unique($tree->server)),'\');"></div>';
									}
									// $tree->title
									echo '</td><td><span class="vulntitle">',$tree->title,'</span>',
									'<div class="code" id="',key($output),$tree->lines[0],'">',"\n";

									if($treestyle == 1)
										traverse_bottom_up($tree);
									else if($treestyle == 2)
										traverse_top_down($tree);

										echo '<ul><li>',"\n";
									dependencies_traverse($tree);
									echo '</li></ul>',"\n",	'</div>',"\n", '</td></tr></table></div>',"\n";
								}
							}	
							
							if(!empty($vulnBlock->alternatives))
							{
								echo '<div class="codebox"><table><tr><td><ul><li><span class="vulntitle">Vulnerability is also triggered in:</span>';
								foreach($vulnBlock->alternatives as $alternative)
								{
									echo '<ul><li>'.$alternative.'</li></ul>';
								}
								echo '</li></ul></td></table></div>';
							}
							
							echo '</div></div><div style="height:20px"></div>',"\n";
						}	
					}

					echo '</div><div class="buttonbox">',"\n",
					'<input type="submit" class="Button" value="hide all" ',
					'onClick="hide(\'',addslashes(key($output)),'\')">',"\n",
					'</div></div><hr>',"\n";
				}	
				else if(count($output) == 1)
				{
					echo '<div style="margin-left:30px;color:#000000">Nothing vulnerable found. Change the verbosity level or vulnerability type  and try again.</div>';
				}
			}
			while(next($output));
		}
		else if(count($GLOBALS['scanned_files']) > 0)
		{
			echo '<div style="margin-left:30px;color:#000000">Nothing vulnerable found. Change the verbosity level or vulnerability type and try again.</div>';
		}
		else
		{
			echo '<div style="margin-left:30px;color:#000000">Nothing to scan. Please check your path/file name.</div>';
		}
		
	}
	*/
	
	/*
	// build list of available functions
	function createFunctionList($user_functions_offset)
	{
		if(!empty($user_functions_offset))
		{
			ksort($user_functions_offset);
			if($GLOBALS['file_amount'] <= WARNFILES)
				$js = 'graph2 = new Graph(document.getElementById("functioncanvas"));'."\n";
			else
				$js = 'canvas = document.getElementById("functioncanvas");ctx = canvas.getContext("2d");ctx.fillStyle="#ff0000";ctx.fillText("Graphs have been disabled for a high file amount (>'.WARNFILES.').", 20, 30);';
			$x=20;
			$y=50;
			$i=0;
			
			if($GLOBALS['file_amount'] <= WARNFILES)
			{
				// create JS graph elements
				foreach($user_functions_offset as $func_name => $info)
				{				
					if($func_name !== '__main__')
					{
						$x = ($i%4==0) ? $x=20 : $x=$x+160;
						$y = ($i%4==0) ? $y=$y+70 : $y=$y;
						$i++;
						
						$func_varname = str_replace('::', '', $func_name);
						
						$js.= "var e$func_varname = graph2.addElement(pageTemplate, { x:$x, y:$y }, '".addslashes($func_name)."( )', '', '".(isset($info[5]) ? $info[5] : 0)."', '".(isset($info[6]) ? $info[6] : 0)."', 0);\n";
					} else
					{	
						$js.='var e__main__ = graph2.addElement(pageTemplate, { x:260, y:20 }, "__main__", "", "'.(isset($info[5]) ? $info[5] : 0).'", "'.(isset($info[6]) ? $info[6] : 0).'", 0);'."\n";
					}	
				}
			}
			
			echo '<div id="functionlistdiv"><table><tr><th align="left">declaration</th><th align="left">calls</th></tr>';
			foreach($user_functions_offset as $func_name => $info)
			{
				if($func_name !== '__main__')
				echo '<tr><td><div id="fol_',$func_name,'" class="funclistline" title="',$info[0],'" ',
				'onClick="openCodeViewer(3, \'',addslashes($info[0]),'\', \'',($info[1]+1),
				',',(!empty($info[2]) ? $info[2]+1 : 0),'\')">',$func_name,'</div></td><td>';
								
				$calls = array();
				if(isset($info[3]))
				{
					foreach($info[3] as $call)
					{
						$calls[] = '<span class="funclistline" title="'.$call[0].
						'" onClick="openCodeViewer(3, \''.addslashes($call[0]).'\', \''.$call[1].'\')">'.$call[1].'</span>';
					}
				}
				echo implode(',',array_unique($calls)).'</td></tr>';
				
				if(isset($info[4]) && $GLOBALS['file_amount'] <= WARNFILES)
				{
					foreach($info[4] as $call)
					{
						if(!is_array($call))
						{
							$color = (isset($info[4][$call])) ? '#F00' : '#000';
							$js.="try{graph2.addConnection(e$call.getConnector(\"links\"), e$func_name.getConnector(\"parents\"), '$color');}catch(e){}\n";
						}	
					}
				}
			}
			if($GLOBALS['file_amount'] <= WARNFILES)
				$js.='graph2.update();';
			echo '</table></div>',"\n<div id='functiongraph_code' style='display:none'>$js</div>\n";
		} else
		{
			echo "<div id='functiongraph_code' style='display:none'>document.getElementById('windowcontent3').innerHTML='No user defined functions found.'</div>\n";
		}
	}
	*/
	
	/*
	// build list of all entry points (user input)
	function createUserinputList($user_input)
	{
		if(!empty($user_input))
		{
			ksort($user_input);
			echo '<table><tr><th align="left">type[parameter]</th><th align="left">taints</th></tr>';
			foreach($user_input as $input_name => $file)
			{
				$finds = array();
				foreach($file as $file_name => $lines)
				{
					foreach($lines as $line)
					{
						$finds[] = '<span class="funclistline" title="'.htmlentities($file_name).'" onClick="openCodeViewer(4, \''.htmlentities($file_name, ENT_QUOTES)."', '$line')\">$line</span>\n";
					}
				}
				echo "<tr><td nowrap>$input_name</td><td nowrap>",implode(',',array_unique($finds)),'</td></tr>';

			}
			echo '</table>';
		} else
		{
			echo 'No userinput found.';
		}
	}
	*/

	/*	
	// build list of all scanned files
	function createFileList($files, $file_sinks)
	{
		if(!empty($files))
		{
			if($GLOBALS['file_amount'] <= WARNFILES)
				$js = 'graph = new Graph(document.getElementById("filecanvas"));'."\n";
			else	
				$js = 'canvas = document.getElementById("filecanvas");ctx = canvas.getContext("2d");ctx.fillStyle="#ff0000";ctx.fillText("Graphs have been disabled for a high file amount (>'.WARNFILES.').", 20, 30);';
	
			// get vuln files
			$vulnfiles = array();
			foreach($GLOBALS['output'] as $fileName => $blocks)
			{		
				foreach($blocks as $block)
				{
					if($block->vuln)
					{
						$vulnfiles[] = $block->treenodes[0]->filename;
					}	
				}	
			}	

			// sort files by "include weight" (main files on top, included files bottom)
			$mainfiles = array();
			$incfiles = array();
			foreach($files as $file => $includes)
			{
				$mainfiles[] = realpath($file);
				if(!empty($includes))
				{
					foreach($includes as $include)
					{
						$incfiles[] = realpath($include);
					}
				}	
			}
			$elements = array_unique(array_merge(array_diff($mainfiles,$incfiles), array('__break__'), $incfiles));
			$x=20;
			$y=-50;
			$i=0;
			$style = 'pageTemplate';

			// add JS elements
			foreach($elements as $file)
			{
				if($file !== '__break__')
				{
					$x = ($i%4==0) ? $x=20 : $x=$x+160;
					$y = ($i%4==0) ? $y=$y+70 : $y=$y;
					$i++;
					
					// leave space for legend symbols
					if($i==3)
						$i++;
					
					$file = realpath($file);

					$fileName = is_dir($_POST['loc']) ? str_replace(realpath($_POST['loc']), '', $file) : str_replace(realpath(str_replace(basename($_POST['loc']),'', $_POST['loc'])),'',$file);
					$varname = preg_replace('/[^A-Za-z0-9]/', '', $fileName); 

					$userinput = 0;
					foreach($GLOBALS['user_input'] as $inputname)
					{
						if(isset($inputname[$file]))
							$userinput++;
					}			
					
					if($GLOBALS['file_amount'] <= WARNFILES)
						$js.= "var e$varname = graph.addElement($style, { x:$x, y:$y }, '".htmlentities($fileName, ENT_QUOTES)."', '', '".$userinput."', '".htmlentities($file_sinks[$file], ENT_QUOTES)."', ".(in_array($file, $vulnfiles) ? 1 : 0).");\n";

				} else
				{
					// add to $i what is missing til new row is created
					$i=$i+(4-($i%4));
					$y+=30;
					$style = 'scriptTemplate';
				}
			}	
			
			// build file list and add connection to includes
			echo '<div id="filelistdiv"><table>';
			foreach($files as $file => $includes)
			{				
				$file = realpath($file);

				$fileName = is_dir($_POST['loc']) ? str_replace(realpath($_POST['loc']), '', $file) : str_replace(realpath(str_replace(basename($_POST['loc']),'', $_POST['loc'])),'',$file);
				$varname = preg_replace('/[^A-Za-z0-9]/', '', $fileName); 

				if(empty($includes))
				{
					echo '<tr><td><div class="funclistline" title="',htmlentities($file),'" ',
					'onClick="openCodeViewer(3, \'',htmlentities($file, ENT_QUOTES),'\', \'0\')">',htmlentities($fileName),'</div></td></tr>',"\n";
				}	
				else
				{
					$parent = $varname;
					echo '<tr><td><div class="funclistline" title="',htmlentities($file),'" ',
					'onClick="openCodeViewer(3, \'',htmlentities($file, ENT_QUOTES),'\', \'0\')">',htmlentities($fileName),'</div><ul style="margin-top:0px;">',"\n";
					foreach($includes as $include)
					{
						$include = realpath($include);
	
						$includename = is_dir($_POST['loc']) ? str_replace(realpath($_POST['loc']), '', $include) : str_replace(realpath(str_replace(basename($_POST['loc']),'', $_POST['loc'])),'',$include);
						$incvarname = preg_replace('/[^A-Za-z0-9]/', '', $includename); 
	
						echo '<li><div class="funclistline" title="',htmlentities($include),'" ',
						'onClick="openCodeViewer(3, \'',htmlentities($include, ENT_QUOTES),'\', \'0\')">',htmlentities($includename),'</div></li>',"\n";
						
						if($GLOBALS['file_amount'] <= WARNFILES)
							$js.="try{graph.addConnection(e$incvarname.getConnector(\"links\"), e$parent.getConnector(\"parents\"), '#000');}catch(e){}\n";
					}
					echo '</ul></td></tr>',"\n";
				}	

			}
			if($GLOBALS['file_amount'] <= WARNFILES)
				$js.='graph.update();';
			echo '</table></div>',"\n<div id='filegraph_code' style='display:none'>$js</div>\n";
		}
	}
	*/
	/*
	function statsRow($nr, $name, $amount, $all)
	{
		echo '<tr><td nowrap onmouseover="this.style.color=\'white\';" onmouseout="this.style.color=\'#DFDFDF\';" onClick="catshow(\'',$name,'\')" style="cursor:pointer;" title="show only vulnerabilities of this category">',$name,':</td><td nowrap><div id="chart'.$nr.'" class="chart" style="width:',
			round(($amount/$all)*100,0),'"></div><div id="vuln'.$nr.'">',$amount,'</div></td></tr>';
	}
	*/
	
?>	