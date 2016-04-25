<?php

class Scanner
{
	public $fileName;
	public $scanFuncs;
	public $srcFuncs;

	public $varDeclaresGlobal;	
	public $globalsFromFunc;
	
	public $inClass;
	public $className;
	public $vulnClasses;
	public $classVars;
	public $braceSaveClass;
		
	public $inFunc;	
	public $funcObj;
	public $varDeclaresLocal;
	public $putInGlobalScope;
	public $braceSaveFunc;
	
	public $bracesOpen;
	public $ignoreRequirement;
	public $dependencies;
	public $dependencytokens;
		
	public $securedby;	
	public $ignoreSecuringFunc;	
	public $userfunction_secures;
	public $userfunction_taints;	
	public $comment;
	
	public $inc_file_stack;
	public $incMap;
	public $inclPaths;
	public $filePointer;
	public $lines_stack;
	public $lines_pointer;
	public $tif;
	public $tifStack;
	
	public $tokens;
		
	function __construct($fileName, $scanFuncs, $srcFuncs)
	{
		$GLOBALS['verbosity'] = 1;

		$this->file_name = $fileName;
		$this->scan_functions = $scanFuncs;		
		$this->source_functions = $srcFuncs;
		
		$this->var_declares_global = array();	
		$this->var_declares_local = array();
		$this->put_in_global_scope = array();
		$this->globals_from_function = array();
		
		$this->in_class = false;
		$this->class_name = '';
		$this->vuln_classes = array();
		$this->class_vars = array();
		
		$this->in_function = 0;
		$this->function_obj = null;
		
		$this->in_condition = 0;
		$this->braces_open = 0;
		$this->brace_save_func = -1;
		$this->brace_save_class = -1;
		$this->ignore_requirement = false;
		$this->dependencies = array();
		$this->dependencytokens = array();
		
		$this->securedby = array();
		$this->ignore_securing_function = false;
		$this->userfunction_secures = false;
		$this->userfunction_taints = false;	
		$this->comment = '';
		
		$this->inc_file_stack = array(realpath($this->file_name));
		$this->inc_map = array();
		$this->include_paths = StringAnalyzer::get_ini_paths(ini_get("include_path"));
		$this->file_pointer = end($this->inc_file_stack);
		if(!isset($GLOBALS['file_sinks_count'][$this->file_pointer]))
			$GLOBALS['file_sinks_count'][$this->file_pointer] = 0;
		$this->lines_stack = array();
		$this->lines_stack[] = file($this->file_name);
		$this->lines_pointer = end($this->lines_stack);
		$this->tif = 0; // tokennr in file
		$this->tif_stack = array();
		
		// preload output
		echo $GLOBALS['fit'] . '|' . $GLOBALS['file_amount'] . '|' . $this->file_pointer . ' (tokenizing)|' . $GLOBALS['timeleft'] . '|' . "\n";
		@ob_flush();
		flush();
		
		// tokenizing
		$tokenizer = new Tokenizer($this->file_pointer);
		$this->tokens = $tokenizer->tokenize(implode('',$this->lines_pointer));
		unset($tokenizer);
		
		// add auto includes from php.ini
		if(ini_get('auto_prepend_file'))
		{
			$this->add_auto_include(ini_get('auto_prepend_file'), true);
		}
		if(ini_get('auto_append_file'))
		{
			$this->add_auto_include(ini_get('auto_append_file'), false);
		}
	}
	
	// create require tokens for auto_prepend/append_files and add to tokenlist
	function add_auto_include($paths, $isBeginning)
	{
		$paths = StringAnalyzer::get_ini_paths($paths);
		$addTokens = array();
		foreach($paths as $file)
		{
			$inclTokens = array(
				array(T_REQUIRE, 'require', 0),
				array(T_CONSTANT_ENCAPSED_STRING, "'$file'", 0), 
				';'
			);
			$addTokens = array_merge($addTokens, $inclTokens);
		}
		if ($isBeginning)
			$this->tokens = array_merge($addTokens, $this->tokens);
		else
			$this->tokens = array_merge($this->tokens, $addTokens);
	}
	
	// traces recursivly parameters and adds them as child to parent
	// returns true if a parameter is tainted by userinput (1=directly tainted, 2=function param)
	function scan_parameter($mainParent, $parent, $varToken, $varKeys=array(), $lastTokenId, $varDeclares, $varDeclaresGlobal=array(), $userInput, $F_SECURES=array(), $returnScan=false, $ignoreSecuring=false, $secured=false)
	{
		#print_r(func_get_args());echo "\n----------------\n";
		$vardependent = false;
		
		$varName = $varToken[1]; 
		// constants
		if($varName[0] !== '$')
		{
			$varName = strtoupper($varName);
		} 
		// variables
		else
		{
			// reconstruct array key values $a[$b]
			if(isset($varToken[3]))
			{
				for($k=0;$k<count($varToken[3]); $k++)
				{
					if(is_array($varToken[3][$k]))
					{
						$varToken[3][$k] = StringAnalyzer::get_tokens_value(
							$this->file_pointer,
							$varToken[3][$k], 
							$varDeclares, 
							$varDeclaresGlobal, 
							$lastTokenId
						);
					}	
				}
			}	
			
			// handle $GLOBALS and $_SESSIONS
			if(isset($varToken[3]))
			{
				if($varName == '$GLOBALS' && !isset($varDeclares[$varName]) && !empty($varToken[3][0]) ) 
				{
					$varName = '$'. str_replace(array("'",'"'), '', $varToken[3][0]);
					// php $GLOBALS: ignore previous local vars and take only global vars
					$varDeclares = $varDeclaresGlobal;
				}
				else if($varName === '$_SESSION' && !isset($varDeclares[$varName]) && !empty($varDeclaresGlobal))
				{
					// $_SESSION data is handled as global variables
					$varDeclares = array_merge($varDeclaresGlobal, $varDeclares);
				}
			}
		
			// if a register_globals implementation is present shift it to the beginning of the var_declare array
			if(isset($varDeclares['register_globals']) && !in_array($varName, Sources::$SRC_USERINPUT)
			&& (!$this->in_function || in_array($varName, $this->put_in_global_scope)))
			{		
				if(!isset($varDeclares[$varName]))
				{
					$varDeclares[$varName] = $varDeclares['register_globals'];
				}	
				else	
				{
					foreach($varDeclares['register_globals'] as $glob_obj)
					{
						if($glob_obj->id < $lastTokenId)
							$varDeclares[$varName][] = $glob_obj;
					}
				}	
			}	
		}

		// check if var declaration could be found for this var
		// and if the latest var_declares id is smaller than the last_token_id, otherwise continue with function parameters		
		# echo "trying: $varName, isset: ".(int)(isset($varDeclares[$varName])).", ".end($varDeclares[$varName])->id." < ".$lastTokenId."?\n";		
		if( isset($varDeclares[$varName]) && (end($varDeclares[$varName])->id < $lastTokenId || $userInput) )
		{		
			foreach($varDeclares[$varName] as $varDeclare)
			{	
				// check if array keys are the same (if it is an array)
				$arrayKeyDiff = array();
				if( !empty($varToken[3]) && !empty($varDeclare->array_keys) )	
					$arrayKeyDiff = array_diff_assoc($varToken[3], $varDeclare->array_keys); 
				
					#print_r($varDeclares[$varName]);		
					#echo "<br>var:".$varName; echo " varkeys:";print_r($varToken[3]); echo " declarekeys:";print_r($varDeclare->array_keys); echo " diff:"; print_r($arrayKeyDiff); echo " |||";

					#if(!empty($varDeclare->array_keys)) die(print_r($varDeclare->array_keys) . print_r($varKeys));

				if( $varDeclare->id < $lastTokenId && (empty($arrayKeyDiff) || in_array('*', $arrayKeyDiff) || in_array('*', $varDeclare->array_keys)) /* && (empty($varDeclare->array_keys) || empty($varKeys) || $varDeclare->array_keys == $varKeys || in_array('*', $varKeys) || in_array('*', $arrayKeyDiff) || in_array('*', $varDeclare->array_keys) ) */  )
				{	
					$comment = '';
					// add line to output
					if(count($mainParent->lines) < MAXTRACE)				
					{
						$clean_vars_before_ifelse = false;
						// add same var_name with different dependencies
						if(!empty($varDeclare->dependencies) && $mainParent->dependencies != $varDeclare->dependencies )
						{							
							foreach($varDeclare->dependencies as $deplinenr=>$dependency)
							{
								if( !isset($mainParent->dependencies[$deplinenr]) && $deplinenr != $varDeclare->line )
								{	
									$vardependent = true;
									$comment.= tokenstostring($dependency).', ';
									// if dependencie has an ELSE clause, same vars before are definetely overwritten
									if($dependency[count($dependency)-1][0] === T_ELSE)
										$clean_vars_before_ifelse = true;
								}
							}
						}

						// stop at var declarations before if else statement. they are overwritten
						if($clean_vars_before_ifelse)
						{
							for($c=0;$c<count($varDeclares[$varName]);$c++)
							{	
								if(count($varDeclares[$varName][$c]->dependencies) < count($varDeclare->dependencies))
								{
									$varDeclares[$varName][$c-1]->stopvar=true;
									break;
								}	
							}
						}
						
						$mainParent->lines[] = $varDeclare->line;	
						$varTrace = new VarDeclare('');
						$parent->children[] = $varTrace;
					} else
					{	
						$stop = new VarDeclare('... Trace stopped.');
						$parent->children[] = $stop; 
						return $userInput;
					}
					
					// find other variables in this line
					$tokens = $varDeclare->tokens;
					$last_scanned = '';
					$lastUserInput = false;
					$inArithmetic = false;
					$inSecuring = false;
					$parenthesesIsOpen = 0;
					$parenthesesSaveState = -1;
					
					$taintedVars = array();
					$var_count = 1;

					for($i = $varDeclare->tokenscanstart; $i < $varDeclare->tokenscanstop; $i++)
					{
						$isSecure = false;
						if( is_array($tokens[$i]) )
						{
							// if token is variable or constant
							if( ($tokens[$i][0] === T_VARIABLE && $tokens[$i+1][0] !== T_OBJECTOKEN_OPERATOR)
							|| ($tokens[$i][0] === T_STRING && $tokens[$i+1] !== '(') )
							{	
								$var_count++;

								// check if typecasted
								if((is_array($tokens[$i-1]) 
								&& in_array($tokens[$i-1][0], Tokens::$TOKEN_CASTS))
								|| (is_array($tokens[$i+1]) 
								&& in_array($tokens[$i+1][0], Tokens::$TOKEN_ARITHMETIC)) )
								{
									// mark user function as a securing user function
									$GLOBALS['userfunction_secures'] = true;
									$isSecure = true;

									$varTrace->marker = 2;
								} 
								
								// check for automatic typecasts by arithmetic
								if(in_array($tokens[$i-1], Tokens::$TOKEN_OPERATOR_C)
								|| in_array($tokens[$i+1], Tokens::$TOKEN_OPERATOR_C) )
								{
									// mark user function as a securing user function
									$GLOBALS['userfunction_secures'] = true;
									
									$inArithmetic = true;
									
									$varTrace->marker = 2;
								}
								
								// scan in global scope
								$userInput = $this->scan_parameter(
									$mainParent, 
									$varTrace, 
									$tokens[$i], 
									$varKeys,
									$varDeclare->id, 
									((is_array($tokens[$i-1]) && $tokens[$i-1][0] === T_GLOBAL) || $tokens[$i][1][0] !== '$') ? $varDeclaresGlobal : $varDeclares,  // global or local scope
									$varDeclaresGlobal, 
									$userInput,
									$F_SECURES, 
									$returnScan, 
									$ignoreSecuring, 
									($isSecure || $inSecuring || $inArithmetic)
								);

								// consider securing applied to parent variable
								if($secured && $GLOBALS['verbosity'] < 3 && !$lastUserInput) 
								{
									$userInput = false;
								}	
								
								// add tainted variable to the list to get them highlighted in output
								if($userInput && !$lastUserInput)
								{
									$taintedVars[] = $var_count;
								}
							}
							// if in foreach($bla as $key=>$value) dont trace $key, $value back
							else if( $tokens[$i][0] === T_AS )
							{
								break;
							}
							// also check for userinput from functions returning userinput
							else if( in_array($tokens[$i][1], $this->source_functions) )
							{
								$userInput = true;
								$varTrace->marker = 4;
								$mainParent->title = 'Userinput returned by function <i>'.$tokens[$i][1].'()</i> reaches sensitive sink.';
								
								if($returnScan)
								{
									$GLOBALS['userfunction_taints'] = true;
								}	
								// userinput received in function, just needs a trigger
								else if($this->in_function)
								{
									$this->add_trigger_function($mainParent);
								}	
								
								// we could return here to not scan all parameters of the tainting function
								// however we would need to add the line manually to the output here
							}
							// detect securing functions
							else if(!$ignoreSecuring && ( (is_array($F_SECURES) && in_array($tokens[$i][1], $F_SECURES))
							|| (isset($tokens[$i][1]) && in_array($tokens[$i][1], $GLOBALS['F_SECURING_STRING'])) 
							|| (in_array($tokens[$i][0], Tokens::$TOKEN_CASTS) && $tokens[$i+1] === '(') )  )
							{
								$parenthesesSaveState = $parenthesesIsOpen;
								$inSecuring = true;
								$this->securedby[] = $tokens[$i][1];
							}
							//detect insecuring functions (functions that make previous securing useless)
							else if( isset($tokens[$i][1]) && in_array($tokens[$i][1], $GLOBALS['F_INSECURING_STRING']))
							{
								$parenthesesSaveState = $parenthesesIsOpen;
								$ignoreSecuring = true;
							}
							// if this is a vuln line, it has already been scanned -> return
							else if( ((in_array($tokens[$i][0], Tokens::$TOKEN_FUNCTIONS) 
							&& isset($GLOBALS['scan_functions'][$tokens[$i][1]])))
							// ignore oftenly used preg_replace() and alike
							&& !isset($GLOBALS['F_CODE'][$tokens[$i][1]]) 
							&& !isset($GLOBALS['F_REFLECTION'][$tokens[$i][1]]) 
							&& !isset($GLOBALS['F_OTHER'][$tokens[$i][1]]))
							{
								$varTrace->value = highlightline($tokens, $comment.$varDeclare->comment.', trace stopped', $varDeclare->line);
								$varTrace->line = $varDeclare->line;
								return $userInput;
							}
							// check for automatic typecasts by arithmetic assignment
							else if(in_array($tokens[$i][0], Tokens::$TOKEN_ASSIGNMENT_SECURE))
							{
								// mark user function as a securing user function
								$GLOBALS['userfunction_secures'] = true;
								$secured = 'arithmetic assignment';

								$userInput = false;	// first variable before operator has alread been traced, ignore
								$varTrace->marker = 2;
							}
							// func_get_args()
							else if($tokens[$i][1] === 'func_get_args' && $this->in_function && $tokens[$i][0] === T_STRING)
							{
								$this->add_function_dependend($mainParent, $parent, $returnScan, -1);
								$userInput = 2;
							}
							// func_get_arg()
							else if($tokens[$i][1] === 'func_get_arg' && $this->in_function && $tokens[$i][0] === T_STRING)
							{
								$this->add_function_dependend($mainParent, $parent, $returnScan, $tokens[$i+2][1]);
								$userInput = 2;
							}
						}
						// string concat disables arithmetic
						else if($tokens[$i] === '.')
						{
							$inArithmetic = false;
						}
						// watch opening parentheses
						else if($tokens[$i] === '(')
						{
							$parenthesesIsOpen++;
						}
						// watch closing parentheses
						else if($tokens[$i] === ')')
						{
							$parenthesesIsOpen--;
							if($parenthesesIsOpen === $parenthesesSaveState)
							{
								$parenthesesSaveState = -1;
								$inSecuring = false;
								$ignoreSecuring = false;
							}
						}
											
						// save userinput (true|false) for vars in same line
						$lastUserInput = $userInput;
					}

					// add highlighted line to output, mark tainted vars
					$varTrace->value = highlightline($tokens, $varDeclare->comment.$comment, $varDeclare->line, false, false, $taintedVars);
					$varTrace->line = $varDeclare->line;
		
					// we only need the last var declaration, other declarations have been overwritten
					// exception: if elseif statements:
					// if else at least overwrites vars before if else statement (else always triggers)
					if( ($userInput || !$vardependent || $varDeclare->stopvar) && !in_array('*', $arrayKeyDiff)) 
						break;
				}
			}
		}
		// if var comes from function parameter AND has not been overwritten with static content before (else)
		else if($this->in_function && in_array($varName, $this->function_obj->parameters) && ($GLOBALS['verbosity'] >= 3 || empty($secured)) )
		{
			$key = array_search($varName, $this->function_obj->parameters);
			$this->add_function_dependend($mainParent, $parent, $returnScan, $key);
			$userInput = 2;
		} 				
		
		// if var is userinput, return true directly	
		if( in_array($varName, Sources::$SRC_USERINPUT) && empty($secured) )
		{
			// check if userinput variable has been overwritten
			$overwritten = false;
			if(isset($varDeclares[$varName]))
			{
				foreach($varDeclares[$varName] as $var)
				{
					// check if array keys are the same (if it is an array)
					$arrayKeyDiff = false;
					if( isset($varToken[3]) && !empty($varDeclare->array_keys) )		
						$arrayKeyDiff = array_diff_assoc($varToken[3], $varDeclare->array_keys);
				
					// if there is a var declare for this userinput !except the same line!: overwritten
					if($lastTokenId != $var->id && !$arrayKeyDiff)
						$overwritten = true;
				}
			}	

			if(!$overwritten)
			{
				// add userinput markers to mainparent object
				if(isset($varToken[3]))
					$parameter_name = str_replace(array("'",'"'), '', $varToken[3][0]);
				else
					$parameter_name = 'x';
				
				// mark tainted, but only specific $_SERVER parameters
				if($varName !== '$_SERVER'
				|| in_array($parameter_name, Sources::$SRC_SERVER_PARAMS) 
				|| substr($parameter_name,0,5) === 'HTTP_')
				{
					$userInput = true;
					$parent->marker = 1;			

					$this->add_exploit_parameter_to_parent($mainParent, $varName, $parameter_name);
					
					// analyse depencies for userinput and add it for exploit creator
					if(!empty($mainParent->dependencies))
					{
						foreach($mainParent->dependencies as $dtokens)
						{
							for($t=0;$t<count($dtokens);$t++)
							{						
								if($dtokens[$t][0] === T_VARIABLE && in_array($dtokens[$t][1], Sources::$SRC_USERINPUT) && ($dtokens[$t][1] !== '$_SERVER' || in_array($dtokens[$t][3][0], Sources::$SRC_SERVER_PARAMS)
								|| substr($dtokens[$t][3][0],0,5) === 'HTTP_'))
								{
									$this->add_exploit_parameter_to_parent($mainParent, $dtokens[$t][1], str_replace(array('"',"'"), '', $dtokens[$t][3][0]));		
								}
							}
						}
					}
				}
							
				// userinput received in function, just needs a trigger
				if($this->in_function && !$returnScan)
				{
					$this->add_trigger_function($mainParent);
				}
			}
		} 
		
		// to avoid False/Positive::2b
        //if ($userInput === 2) {
        //    return 0;
        //}

		return $userInput;
	}
	
	// add exploit parameter to parent
	function add_exploit_parameter_to_parent($parent, $type, $parameter_name)
	{
		if(!empty($parameter_name))
		{
			switch($type)
			{
				case '$_GET': 				$parent->get[] = $parameter_name; break;
				case '$HTTP_GET_VARS': 		$parent->get[] = $parameter_name; break;
				case '$_REQUEST': 			$parent->get[] = $parameter_name; break;
				case '$HTTP_REQUEST_VARS':	$parent->get[] = $parameter_name; break;
				case '$_POST': 				$parent->post[] = $parameter_name; break;
				case '$HTTP_POST_VARS':		$parent->post[] = $parameter_name; break;
				case '$HTTP_RAW_POST_DATA':	$parent->post[] = $parameter_name; break;
				case '$_COOKIE': 			$parent->cookie[] = $parameter_name; break;
				case '$HTTP_COOKIE_VARS':	$parent->cookie[] = $parameter_name; break;
				case '$_FILES': 			$parent->files[] = $parameter_name; break;
				case '$HTTP_POST_FILES':	$parent->files[] = $parameter_name; break;
				case '$_SERVER':			$parent->server[] = $parameter_name; break;
			}
		}
	}
	
	// add function to output that triggers something by call
	function add_trigger_function($mainParent)
	{
		/*
		avoid False/Positive :: dont know the purpose of this function

		// add dependency and mark this as interesting function
		$mainParent->dependencies[$this->function_obj->lines[0]] = $this->function_obj->tokens;
		$mainParent->title = "Userinput reaches sensitive sink when function <i>{$this->function_obj->name}()</i> is called.";
		
		// add function to scanlist
		$mainParent->funcdepend = $this->function_obj->name;
		// with all parameters as valuable since userinput comes from inside the func
		$GLOBALS['user_functions'][$this->file_name][$this->function_obj->name][0][0] = 0;
		// no securings				
		$GLOBALS['user_functions'][$this->file_name][$this->function_obj->name][1] = array();
		// doesnt matter if called with userinput or not
		$GLOBALS['user_functions'][$this->file_name][$this->function_obj->name][3] = true;
		*/
	}
	
	// add function declaration to parent and mark the block as dependend of this function calls
	function add_function_dependend($mainParent, $parent, $returnScan, $key)
	{
		// add child with function declaration
		$func_name = $this->function_obj->name;
		$mainParent->lines[] = $this->function_obj->lines[0];
		if($this->function_obj->marker !== 3)
		{
			$this->function_obj->value = highlightline($this->function_obj->tokens, '', $this->function_obj->lines[0]);
			// mark as potential userinput
			$this->function_obj->marker = 3;
		}
		$parent->children[] = $this->function_obj;
		
		// add function to scanlist
		if(!$returnScan)
		{
			$mainParent->funcdepend = $func_name;
			// $mainParent->funcdependparam != $GLOBALS['user_functions'][$this->file_name][$func_name][0]
			$mainParent->funcparamdepend[] = $key+1;

			// with potential parameters
			$map = $key < 0 ? 0 : $key;
			// scan this userfunction with the vuln parameter
			$GLOBALS['user_functions'][$this->file_name][$func_name][0][$map] = $key+1;
			// and with according securing functions from original find					
			$GLOBALS['user_functions'][$this->file_name][$func_name][1] = isset($GLOBALS['scan_functions'][$mainParent->name][1]) ? $GLOBALS['scan_functions'][$mainParent->name][1] : $GLOBALS['user_functions'][$this->file_name][$mainParent->name][1];
		}
	}
	
	
	// check if securing function is listed as securing that depends on quotes	
	function quote_analysis_needed()
	{
		foreach($this->securedby as $var=>$func)
		{
			if(in_array($func, $GLOBALS['F_QUOTE_ANALYSIS']))
				return true;
		}
		return false;
	}
	

	// add a variable to the varlist
	function variable_add($varName, $tokens, $comment='', $tokenscanstart, $tokenscanstop, $linenr, $id, $array_keys=array(), $additional_keys=array())
	{
		// add variable declaration to beginning of varlist
		$new_var = new VarDeclare($tokens,$this->comment . $comment);
		$new_var->line = $linenr;
		$new_var->id = $id;
		
		if($tokenscanstart) 
			$new_var->tokenscanstart = $tokenscanstart;
		if($tokenscanstop) 
			$new_var->tokenscanstop = $tokenscanstop;

		// add dependencies
		foreach($this->dependencies as $deplinenr=>$dependency)
		{
			if(!empty($dependency))
			$new_var->dependencies[$deplinenr] = $dependency;
		}
		
		// if $GLOBALS['x'] is used outside a function its the same as using var $x, rewrite
		if($varName === '$GLOBALS' && !empty($array_keys) && !$this->in_function)
		{
			$varName = '$'.array_shift($array_keys);
		}

		// add additional array keys
		if(!empty($additional_keys))
		{
			if(empty($array_keys))
				$array_keys[] = $additional_keys;
			else	
				$array_keys = array_merge($array_keys, array($additional_keys));
		}
		
		// add/resolve array keys
		if(!empty($array_keys))
		{
			foreach($array_keys as $key)
			{
				if(!is_array($key))
					$new_var->array_keys[] = $key;	
				else
				{
					$recstring = StringAnalyzer::get_tokens_value(
						$this->file_pointer,
						$key, 
						$this->in_function ? $this->var_declares_local : $this->var_declares_global, 
						$this->var_declares_global, 
						$id
					);
					
					if(!empty($recstring))
						$new_var->array_keys[] = $recstring;
					else
						$new_var->array_keys[] = '*';
				}	
			}
		}				
					
		if($this->in_function)
		{
			if(!isset($this->var_declares_local[$varName]))
				$this->var_declares_local[$varName] = array($new_var);
			else
				array_unshift($this->var_declares_local[$varName], $new_var);	

			// if variable was put in global scope, save assignments
			// later they will be pushed to the global var list when function is called
			if(in_array($varName, $this->put_in_global_scope))
			{
				if(!isset($this->globals_from_function[$this->function_obj->name][$varName]))
					$this->globals_from_function[$this->function_obj->name][$varName] = array($new_var);
				else
					array_unshift($this->globals_from_function[$this->function_obj->name][$varName], $new_var);
			}				
		} else
		{
			if(!isset($this->var_declares_global[$varName]))
				$this->var_declares_global[$varName] = array($new_var);
			else
				array_unshift($this->var_declares_global[$varName], $new_var);	
		}
	}
	
	// scans variable for $$dynamic vars or $dynamic() function calls
	function variable_scan($i, $offset, $category, $title)
	{
		if(isset($this->scan_functions[$category]))
		{
			// build new find					 
			$new_find = new VulnTreeNode();
			$new_find->name = $category;
			$new_find->lines[] = $this->tokens[$i][2];
						
			// count sinks
			$GLOBALS['file_sinks_count'][$this->file_pointer]++;

			if($this->in_function)
			{
				$GLOBALS['user_functions_offset'][$this->function_obj->name][6]++;
			} else
			{
				$GLOBALS['user_functions_offset']['__main__'][6]++;
			}			
						
			// add dependencies
			foreach($this->dependencies as $deplinenr=>$dependency)
			{
				if(!empty($dependency))
					$new_find->dependencies[$deplinenr] = $dependency;
			}
							
			// trace back parameters and look for userinput
			$userInput = $this->scan_parameter(
				$new_find, 
				$new_find, 
				$this->tokens[$i], 
				$this->tokens[$i][3],
				$i,
				$this->in_function ? $this->var_declares_local : $this->var_declares_global, 
				$this->var_declares_global, 
				false, 
				array()
			);
							
			// add find to output if function call has variable parameters (With userinput)
			if( $userInput || $GLOBALS['verbosity'] == 4 ) 
			{
				$new_find->filename = $this->file_pointer;
				$new_find->value = highlightline(array_slice($this->tokens, $i-$offset, $offset+3+StringAnalyzer::getBraceEnd($this->tokens, $i+2)), $this->comment, $this->tokens[$i][2], $this->tokens[$i][1], false, array(1));		
							
				// add to output														
				$new_find->title = $title;
				$block = new VulnBlock($this->tif.'_'.$this->tokens[$i][2].'_'.basename($this->file_pointer), getVulnNodeTitle($category), $this->tokens[$i][1]);
				$block->treenodes[] = $new_find;
								
				if($userInput == 1 || $GLOBALS['verbosity'] == 4)
				{
					$block->vuln = true;
					increaseVulnCounter($category);
				}
								
				$GLOBALS['output'][$this->file_name][] = $block;
								
				if($this->in_function)
				{
					$this->ignore_securing_function = true;
					// mark function in class as vuln
					if($this->in_class)
					{
						$this->vuln_classes[$this->class_name][] = $this->function_obj->name;
					}	
				}
				
				// add register_globals implementation
				if($category === 'extract')
				{				
					$this->variable_add(
						'register_globals', 
						array_merge(array_slice($this->tokens, $i-$offset, ($end=$offset+3+StringAnalyzer::getBraceEnd($this->tokens, $i+2))),array(array(T_COMMENT,'// is like ',0),array(T_STRING,'import_request_variables',0),'(',')')), 
						'see above', 
						1, $end+2, 
						$this->tokens[$i][2], 
						$i, 
						isset($this->tokens[$i][3]) ? $this->tokens[$i][3] : array()
					);	

				}
			}	
		}	
	}	
	

	// check if same vulnBlock with the same unique identifier has already been scanned	
	function already_scanned($i)
	{
		$uid = $this->tif.'_'.$this->tokens[$i][2].'_'.basename($this->file_pointer);
		foreach($GLOBALS['output'] as $file)
		{
			foreach($file as $vulnBlock)
			{
				if($vulnBlock->uid == $uid && $vulnBlock->vuln)
				{
					$vulnBlock->alternatives[] = $this->file_name;
					return true;
				}	
			}
		}
		return false;
	}
		
	// parse tokens of php file, build program model, follow program flow, initiate taint analysis	
	function parse()		//*
	{
		// scan all tokens
		for($i = 0, $tokenCount = count($this->tokens); $i < $tokenCount;  $i++, $this->tif++)
		{		
			if( is_array($this->tokens[$i]) )
			{
				$tokenName = $this->tokens[$i][0];
				$tokenValue = $this->tokens[$i][1];
				$lineNr = $this->tokens[$i][2];
				
				// add preloader info for big files
				if($lineNr  % PRELOAD_SHOW_LINE == 0)
				{
					echo $GLOBALS['fit'] . '|' . $GLOBALS['file_amount'] . '|' . $this->file_pointer . ' (line ' . $lineNr  . ')|' . $GLOBALS['timeleft'] . '|' . "\n";
					@ob_flush();
					flush();
				}


				// --- [ T_VARIABLE ] ------------------------------------------
				if($tokenName === T_VARIABLE)
				{
					// $var()
					if($this->tokens[$i+1][0] === '(')
					{
						/* GuruWS
						$this->variable_scan($i, 0, 'eval', 'Userinput is used as dynamic function name. Arbitrary functions may be called.');
						*/
					}
					// $$var = 
					else if( ($this->tokens[$i-1] === '$' || ($this->tokens[$i-1] === '{' && $this->tokens[$i-2] === '$')) && ($this->tokens[$i+1] === '=' || in_array($this->tokens[$i+1][0], Tokens::$TOKEN_ASSIGNMENT)) )
					{
						/* GuruWS
						$this->variable_scan($i, $this->tokens[$i-1] === '{' ? 2 : 1, 'extract', 'Userinput is used to build the variable name. Arbitrary variables may be overwritten/initialized which may lead to further vulnerabilities.');
						*/
					}
					// foreach($var as $key => $value)
					else if( $this->tokens[$i-1][0] === T_AS 
					|| ($this->tokens[$i-1][0] === T_DOUBLE_ARROW && $this->tokens[$i-2][0] === T_VARIABLE && $this->tokens[$i-3][0] === T_AS) )
					{
						$c=3;
						while($this->tokens[$i-$c][0] !== T_FOREACH) 
						{
							$c++;
							
							if(($i-$c)<0 || $this->tokens[$i-$c] === ';')
							{
								add_error('Syntax error !!! GR152');
								break;	
							}
						}

						$this->variable_add(
							$tokenValue, 
							array_slice($this->tokens, $i-$c, $c+StringAnalyzer::getBraceEnd($this->tokens, $i)), 
							'', 
							0, 0, 
							$lineNr, 
							$i, 
							isset($this->tokens[$i][3]) ? $this->tokens[$i][3] : array()
						);	
					}
					// for($var=1; ...)	: add whole instruction block to output	
					else if( $this->tokens[$i-2][0] === T_FOR 
					&& ($this->tokens[$i+1] === '=' || in_array($this->tokens[$i+1][0], Tokens::$TOKEN_ASSIGNMENT)) )
					{
						$c=1;
						$newBraceOpen = 1;
						$firstsemi = 0;
						// do not use getBraceEnd() here, because we dont want to stop at ';' in for(;;)
						while( $newBraceOpen !== 0 )
						{
							// watch function calls in function call
							if( $this->tokens[$i + $c] === '(' )
							{
								$newBraceOpen++;
							}
							else if( $this->tokens[$i + $c] === ')' )
							{
								$newBraceOpen--;
							}					
							else if( $this->tokens[$i + $c] === ';' && $firstsemi < 1 )
							{
								$firstsemi = $c;
							}
							$c++;
							
							if(!isset($this->tokens[$i+$c]))
							{
								add_error('Syntax error !!! GR122');
								break;	
							}
						}

						// overwrite value of first var because it is looped
						// this is an assumption, other vars could be declared for($var1=1;$var2=2;...)
						$this->tokens[$i+2][0] = T_ENCAPSED_AND_WHITESPACE;
						$this->tokens[$i+2][1] = '*';
						
						$this->variable_add(
							$tokenValue, 
							array_slice($this->tokens, $i-2, $c+2), 
							'', 
							1, 2+$firstsemi, 
							$lineNr, 
							$i, 
							isset($this->tokens[$i][3]) ? $this->tokens[$i][3] : array()
						);
					}
					// $var = ...;	
					else if( $this->tokens[$i+1] === '=' || in_array($this->tokens[$i+1][0], Tokens::$TOKEN_ASSIGNMENT) )
					{	
						$vardeclare = array();

						// $var = array(1,2,3,4);
						if($this->tokens[$i+2][0] === T_ARRAY && $this->tokens[$i+3] === '(' && $this->tokens[$i+4] !== ')')
						{
							$d = 4;
							$keyindex = 0;
							$newBraceOpen = 1;
							$keytokens = array();
							$valuetokens = array();

							while( !($newBraceOpen === 0 || $this->tokens[$i + $d] === ';') 
							&& $keyindex < MAX_ARRAY_ELEMENTS )
							{
								// count parameters
								if( $newBraceOpen === 1 && ($this->tokens[$i + $d] === ',' || $this->tokens[$i + $d] === ')' ))
								{
									$newindexvar = $this->tokens[$i];
									$newindexvar[3][] = empty($keytokens) ? $keyindex : $keytokens;

									$this->variable_add(
										$tokenValue, 
										array_merge(array($newindexvar,$this->tokens[$i+1]), $valuetokens), 
										' array() ', 
										in_array($this->tokens[$i+1][0], Tokens::$TOKEN_ASSIGNMENT) ? 0 : 1, 0, 
										$lineNr, 
										$i, 
										isset($this->tokens[$i][3]) ? $this->tokens[$i][3] : array(), 
										empty($keytokens) ? $keyindex : $keytokens
									);

									$keyindex++;
									$keytokens = array();
									$valuetokens = array();
								}
								// watch function calls in array braces
								else if( $this->tokens[$i + $d] === '(' )
								{
									$newBraceOpen++;
								}
								else if( $this->tokens[$i + $d] === ')' )
								{
									$newBraceOpen--;
								}
								// "=>" detected, tokens before are keyname, next one value
								else if( $this->tokens[$i + $d][0] === T_DOUBLE_ARROW )
								{
									$keytokens = $valuetokens;
									$valuetokens = array();
								}
								// main
								else
								{
									$valuetokens[] = $this->tokens[$i + $d];
								}
								$d++;
								
								if(!isset($this->tokens[$i+$d]))
								{
									add_error('Syntax error !!! GR299');
									break;	
								}
							}
							$vardeclare['end'] = StringAnalyzer::getBraceEnd($this->tokens, $i)+1;
						// $var = anything;	
						} else
						{
							$this->variable_add(
								$tokenValue, 
								array_slice($this->tokens, $i, $vardeclare['end'] = StringAnalyzer::getBraceEnd($this->tokens, $i)+1), 
								'',
								in_array($this->tokens[$i+1][0], Tokens::$TOKEN_ASSIGNMENT) ? 0 : 1, 0,
								$lineNr, 
								$i, 
								isset($this->tokens[$i][3]) ? $this->tokens[$i][3] : array()
							);
						}
						// save var and var declare scope for data leak scan
						$vardeclare['start'] = $i;
						$vardeclare['name'] = $tokenValue;
						$vardeclare['linenr'] = $lineNr;
						$vardeclare['end'] += $i-1;
					}
					
					// $class->var
					//else if ($tokenName === T_STRING && $tokens[$i-1][0] === T_OBJECTOKEN_OPERATOR && $tokens[$i-2][0] === T_VARIABLE)	
					
					// add user input variables to global finding list
					if( in_array($tokenValue, Sources::$SRC_USERINPUT) )
					{
						if(isset($this->tokens[$i][3]))
						{
							if(!is_array($this->tokens[$i][3][0]))
								$GLOBALS['user_input'][$tokenValue.'['.$this->tokens[$i][3][0].']'][$this->file_pointer][] = $lineNr;
							else
								$GLOBALS['user_input'][$tokenValue.'['.StringAnalyzer::get_tokens_value(
									$this->file_pointer,
									$this->tokens[$i][3][0],
									$this->in_function ? $this->var_declares_local : $this->var_declares_global,
									$this->var_declares_global, 
									$i
								).']'][$this->file_pointer][] = $lineNr;
						}	
						else
							$GLOBALS['user_input'][$tokenValue][$this->file_pointer][] = $lineNr;	
							
						// count found userinput in function for graphs	
						if($this->in_function)
						{
							$GLOBALS['user_functions_offset'][$this->function_obj->name][5]++;
						} else
						{
							$GLOBALS['user_functions_offset']['__main__'][5]++;
						}
					}
				}
				
				// check if token is a function call and a function to scan
				// do not check if next token is '(' because: require $inc; does not use ()
				else if( in_array($tokenName, Tokens::$TOKEN_FUNCTIONS) 	
				|| (in_array($tokenName, Tokens::$TOKEN_XSS) && ($_POST['vector'] == 'client' || $_POST['vector'] == 'xss' || $_POST['vector'] == 'all')) )
				{		
					$class='';

					// --- [ T_STRING ] ------------------------------------------					

					if($tokenName === T_STRING && $this->tokens[$i+1] === '(')
					{
						// define("FOO", $_GET['asd']);
						if($tokenValue === 'define')
						{
							$c=1;
							while($this->tokens[$i+$c] !== ',')
							{
								$c++;
								
								if($this->tokens[$i+$c] === ';' || !isset($this->tokens[$i+$c]))
								{
									add_error('Second parameter of define() is missing. (GR233)');
									break;	
								}
							}
								
							$this->variable_add(
								str_replace(array('"',"'"), '', $this->tokens[$i+2][1]), 
								array_slice($this->tokens, $i, StringAnalyzer::getBraceEnd($this->tokens, $i)+1), 
								' define() ', 
								$c, 0, 
								$lineNr, 
								$i
							);	
						}
						// ini_set()
						else if($tokenValue === 'ini_set') 
						{
							$setting = str_replace(array("'", '"'), '', $this->tokens[$i+2][1]);
							// ini_set('include_path', 'foo/bar')
							if ($setting === 'include_path')
							{
								$path = StringAnalyzer::get_tokens_value(
									$this->file_pointer,
									array_slice($this->tokens, $i+4,StringAnalyzer::getBraceEnd($this->tokens, $i+4)+1), 
									$this->in_function ? $this->var_declares_local : $this->var_declares_global, 
									$this->var_declares_global, 
									$i
								);
								$this->include_paths = array_unique(array_merge($this->include_paths, StringAnalyzer::get_ini_paths($path)));
							}
						}
						// set_include_path('foo/bar')
						else if($tokenValue === 'set_include_path')
						{
							$path = StringAnalyzer::get_tokens_value(
								$this->file_pointer,
								array_slice($this->tokens, $i+1,StringAnalyzer::getBraceEnd($this->tokens, $i+1)+1), 
								$this->in_function ? $this->var_declares_local : $this->var_declares_global, 
								$this->var_declares_global, 
								$i
							);
							$this->include_paths = array_unique(array_merge($this->include_paths, StringAnalyzer::get_ini_paths($path)));
						}
						// treat error handler as called function
						else if($tokenValue === 'set_error_handler')
						{
							$tokenValue = str_replace(array('"',"'"), '', $this->tokens[$i+2][1]);
						}	
						// $array = compact("event", "city");
						else if($tokenValue === 'compact'  
						&& $this->tokens[$i-2][0] === T_VARIABLE)
						{
							$f=2;
							while( $this->tokens[$i+$f] !== ')' )
							{
								// for all array keys save new variable declarations
								if($this->tokens[$i+$f][0] === T_CONSTANT_ENCAPSED_STRING)
								{						
									$this->variable_add(
										$this->tokens[$i-2][1], array(
											array( T_VARIABLE, $this->tokens[$i-2][1], $lineNr, array(str_replace(array('"',"'"),'',$this->tokens[$i+$f][1])) ),
											'=',
											array(T_VARIABLE, '$'.str_replace(array('"',"'"), '', $this->tokens[$i+$f][1]), $lineNr),
											';'
										), 
										' compact() ', 
										2, 0, 
										$lineNr, 
										$i, 
										$tokens[$i-2][3], 
										str_replace(array('"',"'"),'',$this->tokens[$i+$f][1])
									);
								}
								$f++;
								
								if($this->tokens[$i+$f] === ';' || !isset($this->tokens[$i+$f]))
								{
									add_error('Syntax error !!! (GR9923)');
									break;	
								}
							}
						}	
						// preg_match($regex, $source, $matches), save $matches as var declare	
						else if($tokenValue === 'preg_match' || $tokenValue === 'preg_match_all')
						{
							$c = 2;
							$parameter = 1;
							$newBraceOpen = 1;
							
							while( $newBraceOpen !== 0 )
							{
								if( is_array($this->tokens[$i + $c]) 
								&& $this->tokens[$i + $c][0] === T_VARIABLE && $parameter == 3)
								{
									// add variable declaration to beginning of varlist
									// fake assignment parameter so it will not get traced			
									$this->variable_add(
										$this->tokens[$i + $c][1], 
										array_slice($this->tokens,$i,StringAnalyzer::getBraceEnd($this->tokens,$i+2)+3), 
										' preg_match() ', 
										0, $c-1, 
										$this->tokens[$i + $c][2], 
										$i, 
										isset($this->tokens[$i+$c][3]) ? $this->tokens[$i+$c][3] : array()
									);
								}
								// count parameters
								else if( $newBraceOpen === 1 && $this->tokens[$i + $c] === ',' )
								{
									$parameter++;
								}
								// watch function calls in function call
								else if( $this->tokens[$i + $c] === '(' )
								{
									$newBraceOpen++;
								}
								else if( $this->tokens[$i + $c] === ')' )
								{
									$newBraceOpen--;
								}						
								else if($this->tokens[$i+$c] === ';' || !isset($this->tokens[$i+$c]))
								{
									add_error('Syntax error !!! (GR0101)');
									break;	
								}
								$c++;
							}
						}
						// import_request_variables()
						else if($tokenValue === 'import_request_variables')
						{
							// add register_globals implementation
							$this->variable_add(
								'register_globals', 
								array_slice($this->tokens, $i, StringAnalyzer::getBraceEnd($this->tokens, $i+1)+1), 
								'register_globals implementation', 
								0, 0, 
								$lineNr, 
								$i, 
								isset($this->tokens[$i][3]) ? $this->tokens[$i][3] : array()
							);	
						}
						// parse_str()
						else if($tokenValue === 'parse_str')
						{
							$c = 2;
							$parameter = 1;
							$newBraceOpen = 1;
							
							while( $newBraceOpen !== 0 )
							{
								if( is_array($this->tokens[$i + $c]) 
								&& $this->tokens[$i + $c][0] === T_VARIABLE && $parameter == 2)
								{
									// add variable declaration to beginning of varlist
									// fake assignment parameter so it will not get traced			
									$this->variable_add(
										$this->tokens[$i + $c][1], 
										array_slice($this->tokens,$i,StringAnalyzer::getBraceEnd($this->tokens,$i+2)+3), 
										' parse_str() ', 
										0, $c-1, 
										$this->tokens[$i + $c][2], 
										$i, 
										isset($this->tokens[$i+$c][3]) ? $this->tokens[$i+$c][3] : array()
									);
								}
								// count parameters
								else if( $newBraceOpen === 1 && $this->tokens[$i + $c] === ',' )
								{
									$parameter++;
								}
								// watch function calls in function call
								else if( $this->tokens[$i + $c] === '(' )
								{
									$newBraceOpen++;
								}
								else if( $this->tokens[$i + $c] === ')' )
								{
									$newBraceOpen--;
								}						
								else if($this->tokens[$i+$c] === ';' || !isset($this->tokens[$i+$c]))
								{
									add_error('Syntax error !!! (GR9929) ');
									break;	
								}
								$c++;
							}
						}						

						//add interesting function calls to info gathering	
						/* TODO: remove						
						if( isset($this->info_functions[$tokenValue]) )
						{
							$GLOBALS['info'][] = $this->info_functions[$tokenValue];
						}
						*/	
						// watch constructor calls $var = Classname($constructor_param);
						else if( $this->tokens[$i-1][0] !== T_NEW && isset($this->vuln_classes[$tokenValue]) )
						{
							$this->class_vars[ $this->tokens[$i-2][1] ] = $tokenValue;
						}
						// add function call to user-defined function list
						else
						{
							// $classvar->bla()
							if($this->tokens[$i-1][0] === T_OBJECTOKEN_OPERATOR)
							{
								$classvar = $this->tokens[$i-2][1];
								if($classvar[0] !== '$')
									$classvar = '$'.$classvar;
								$class = ($classvar === '$this' || $classvar === '$self') ? $this->class_name : $this->class_vars[$classvar];
							}	
							// CLASS::func()
							else if($this->tokens[$i-1][0] === T_DOUBLE_COLON)
							{
								$class = $this->tokens[$i-2][1];
							}
							
							// save function call for graph
							if(isset($GLOBALS['user_functions_offset'][($class?$class.'::':'').$tokenValue]))
							{				
								$GLOBALS['user_functions_offset'][($class?$class.'::':'').$tokenValue][3][] = array($this->file_pointer, $lineNr);

								if($this->in_function)
								{
									$GLOBALS['user_functions_offset'][$this->function_obj->name][4][] = $tokenValue;
								} else
								{
									$GLOBALS['user_functions_offset']['__main__'][4][] = $tokenValue;
								}
							}
								
							// check if token is function call that affects variable scope (global)
							if( isset($this->globals_from_function[$tokenValue]) )
							{	
								// put all previously saved global var assignments to global scope
								foreach($this->globals_from_function[$tokenValue] as $varName=>$new_vars)
								{
									foreach($new_vars as $new_var)
									{
										$new_var->comment = $new_var->comment . " by $tokenValue()";
										if(!isset($this->var_declares_global[$varName]))
											$this->var_declares_global[$varName] = array($new_var);
										else
											array_unshift($this->var_declares_global[$varName], $new_var);
									}		
								}
							}
						}
					} 

					// --- [ FILE INCLUSION ] ------------------------------------------					

					// include tokens from included files
					else if( in_array($tokenName, Tokens::$TOKEN_INCLUDES) && !$this->in_function)
					{						
						$GLOBALS['count_inc']++;
						// include('xxx')
						if ( (($this->tokens[$i+1] === '(' 
							&& $this->tokens[$i+2][0] === T_CONSTANT_ENCAPSED_STRING
							&& $this->tokens[$i+3] === ')')
						// include 'xxx'
						|| (is_array($this->tokens[$i+1])
							&& $this->tokens[$i+1][0] === T_CONSTANT_ENCAPSED_STRING
							&& $this->tokens[$i+2] === ';' )) )
						{					
							// include('file')
							if($this->tokens[$i+1] === '(')
							{
								$inc_file = substr($this->tokens[$i+2][1], 1, -1);
								$skip = 5;
							}
							// include 'file'
							else
							{
								$inc_file = substr($this->tokens[$i+1][1], 1, -1);
								$skip = 3;
							}	
						}
						// dynamic include
						else
						{
							$inc_file = StringAnalyzer::get_tokens_value(
								$this->file_pointer,
								array_slice($this->tokens, $i+1, $c=StringAnalyzer::getBraceEnd($this->tokens, $i+1)+1), 
								$this->in_function ? $this->var_declares_local : $this->var_declares_global, 
								$this->var_declares_global, 
								$i
							);

							// in case the get_var_value added several php files, take the first
							$several = explode('.php', $inc_file);
							if(count($several) > 1)
								$try_file = $several[0] . '.php';
				
							$skip = $c+1; // important to save $c+1 here
						}

						$try_file = $inc_file;

						// try absolute include path
						foreach($this->include_paths as $include_path)
						{
							if(is_file("$include_path/$try_file"))
							{
								$try_file = "$include_path/$try_file";	
								break;
							}
						}

						// if dirname(__FILE__) appeared it was an absolute path
						if(!is_file($try_file))
						{
							// check relativ path
							$try_file = dirname($this->file_name). '/' . $inc_file;
							
							
							if(!is_file($try_file))
							{
								$other_try_file = dirname($this->file_pointer). '/' . $inc_file;
								
								// if file can not be found check include_path if set
								if(!is_file($other_try_file)) 
								{
									if(isset($this->include_paths[0]))
									{
										foreach($this->include_paths as $include_path)
										{
											if(is_file(dirname($this->file_name).'/'.$include_path.'/'.$inc_file))
											{
												$try_file = dirname($this->file_name).'/'.$include_path.'/'.$inc_file;
												break;
											}
											else if(is_file(dirname($this->file_pointer).'/'.$include_path.'/'.$inc_file))
											{
												$try_file = dirname($this->file_pointer).'/'.$include_path.'/'.$inc_file;
												break;
											}
										}
									}
									
									// if still not a valid file, look a directory above
									if(!is_file($try_file))
									{
										$try_file = str_replace('\\', '/', $try_file);
										$pos = strlen($try_file);
										// replace each found / with /../, start from the end of file name
										for($c=1; $c<substr_count($try_file, '/'); $c++)
										{
											$pos = strripos(substr($try_file,1,$pos), '/');
											if(is_file(substr_replace($try_file, '/../', $pos+1, 1)))
											{
												$try_file = substr_replace($try_file, '/../', $pos+1, 1);
												break;
											}
										}
									
										if(!is_file($try_file))
										{
											$try_file = str_replace('\\', '/', $other_try_file);
											$pos = strlen($try_file);
											// replace each found / with /../, start from the end of file name
											for($c=1; $c<substr_count($try_file, '/'); $c++)
											{
												$pos = strripos(substr($try_file,1,$pos), '/');
												if(is_file(substr_replace($try_file, '/../', $pos+1, 1)))
												{
													$try_file = substr_replace($try_file, '/../', $pos+1, 1);
													break;
												}
											}
									
											// if still not a valid file, guess it
											if(!is_file($try_file))
											{
												$searchfile = basename($try_file);
												if(!strstr($searchfile, '$_USERINPUT'))
												{
													foreach($GLOBALS['files'] as $cfile)
													{
														if(basename($cfile) == $searchfile)
														{
															$try_file = $cfile;
															break;
														}
													}
												}
											}
										
										}
									}
								} 
								else
								{
									$try_file = $other_try_file;
								}
							} 
						}
						
						$try_file_unreal = $try_file;
						$try_file = realpath($try_file);

						// file is valid
						if(!empty($try_file_unreal) && !empty($try_file) && $inc_lines = @file( $try_file_unreal ))
						{
							// file name has not been included
							if(!in_array($try_file, $this->inc_map))
							{	
								// Tokens
								$tokenizer = new Tokenizer($try_file);
								$inc_tokens = $tokenizer->tokenize(implode('',$inc_lines));
								unset($tokenizer);

								// if(include('file')) { - include tokens after { and not into the condition :S
								if($this->in_condition)
								{
									$this->tokens = array_merge(
										array_slice($this->tokens, 0, $this->in_condition+1), 	// before include in condition
										$inc_tokens, 											// included tokens
										array(array(T_INCLUDE_END, 0, 1)), 						// extra END-identifier
										array_slice($this->tokens, $this->in_condition+1) 		// after condition
									);
								} else
								{
									// insert included tokens in current tokenlist and mark end
									$this->tokens = array_merge(
										array_slice($this->tokens, 0, $i+$skip), 			// before include
										$inc_tokens, 										// included tokens
										array(array(T_INCLUDE_END, 0, 1)), 					// extra END-identifier
										array_slice($this->tokens, $i+$skip) 				// after include
									);
								}
								
								$tokenCount = count($this->tokens);
								
								// set lines pointer to included lines, save last pointer
								// (the following tokens will be the included ones)
								$this->lines_stack[] = $inc_lines;
								$this->lines_pointer = end($this->lines_stack);
								
								// tokennr in file
								$this->tif_stack[] = $this->tif;
								$this->tif = -$skip;
								
								// set the current file pointer
								$this->file_pointer = $try_file;
								if(!isset($GLOBALS['file_sinks_count'][$this->file_pointer]))
									$GLOBALS['file_sinks_count'][$this->file_pointer] = 0;

								echo $GLOBALS['fit'] . '|' . $GLOBALS['file_amount'] . '|' . $this->file_pointer . '|' . $GLOBALS['timeleft'] . '|' ."\n";
								@ob_flush();
								flush();
														
								$this->comment = basename($inc_file);
								
								$this->inc_file_stack[] = $try_file;	

								// build include map for file list
								$this->inc_map[] = $try_file; // all basic includes
							} 
						}
						// included file name could not be reversed 
						// (probably dynamic with function calls)
						else
						{
							$GLOBALS['count_inc_fail']++;
							// add information about include error in debug mode
							if( $GLOBALS['verbosity'] == 5 )
							{
								// add include command to output
								$found_value = highlightline(array_slice($this->tokens,$i,$skip), $this->comment, $lineNr, $tokenValue);
								$new_find = new InfoTreeNode($found_value);
								$new_find->lines[] = $lineNr;
								$new_find->filename = $this->file_pointer;
								$new_find->title =  "Include error: tried to include: ".$try_file_unreal;
								
								if(isset($GLOBALS['output'][$this->file_name]['inc']))
								{
									$GLOBALS['output'][$this->file_name]['inc']->treenodes[] = $new_find;
								}
								else
								{
									$new_block = new VulnBlock($this->tif.'_'.$this->tokens[$i][2].'_'.basename($this->file_pointer), 'Debug');
									$new_block->treenodes[] = $new_find;
									$new_block->vuln = true;
									$GLOBALS['output'][$this->file_name]['inc'] = $new_block;
								}
							}
						}
						
					}	

					//*
					
					// --- [ Taint analysis ] ------------------------------------------

					if(isset($this->scan_functions[$tokenValue]) && $GLOBALS['verbosity'] != 5
					// not a function of a class or a function of a vulnerable class
					&& (empty($class) || (($this->in_function && is_array($funcObj->parameters) && in_array($classvar, $funcObj->parameters)) || @in_array($tokenValue, $this->vuln_classes[$class]))) )
						// GuruWS: pass this
					{	
						if(!$this->already_scanned($i))		// GuruWS: WTF ???
						{
							// build new find					 
							$new_find = new VulnTreeNode();
							$new_find->name = $tokenValue;
							$new_find->lines[] = $lineNr;
							
							// add dependencies (already here, because checked during var trace
							foreach($this->dependencies as $deplinenr=>$dependency)
							{
								if(!empty($dependency))
									$new_find->dependencies[$deplinenr] = $dependency;
							}	
							
							// count sinks
							$GLOBALS['file_sinks_count'][$this->file_pointer]++;

							if($this->in_function)
							{
								$GLOBALS['user_functions_offset'][$this->function_obj->name][6]++;
							} else
							{
								$GLOBALS['user_functions_offset']['__main__'][6]++;
							}

							$parameter = 1;
							$var_counter = 0;
							$vulnparams = array(0);
							$has_vuln_parameters = false;
							$parameter_has_userinput = false;
							$parameter_func_depend = false;
							$secured_by_start = false;
							// function calls without quotes (require $inc;) --> no brace count
							$parenthesesIsOpen = ($this->tokens[$i+1] === '(') ? 1 : -2; // -2: detection of braces doesnt matter
							$parenthesesSaveState = -1;
							$inSecuring = false;
							$ignoreSecuring = false;
							$c = ($this->tokens[$i+1] === '(') ? 2 : 1; // important
							$taintedVars = array();
							
							$reconstructstr = '';
							$addtitle='';
							$this->securedby = array();

							// get all variables in parameter list between (...)
							// not only until ';' because: system(get($a),$b,strstr($c));
							while( $parenthesesIsOpen !== 0 && $this->tokens[$i + $c] !== ';' )
							{
								$isSecure = false;
								if( is_array($this->tokens[$i + $c]) )
								{	
									// scan variables and constants
									if( ($this->tokens[$i + $c][0] === T_VARIABLE && $this->tokens[$i + $c +1][0] !==T_OBJECTOKEN_OPERATOR)
									|| ($this->tokens[$i + $c][0] === T_STRING && $this->tokens[$i + $c+1] !== '(') )
									{
										$var_counter++;
										// scan only potential vulnerable parameters of function call
										if ( in_array($parameter, $this->scan_functions[$tokenValue][0]) 
										|| (isset($this->scan_functions[$tokenValue][0][0])
											&& $this->scan_functions[$tokenValue][0][0] === 0) ) // all parameters accepted
										{			
											$has_vuln_parameters = true;

											if((is_array($this->tokens[$i+$c-1]) 
											&& in_array($this->tokens[$i+$c-1][0], Tokens::$TOKEN_CASTS))
											|| (is_array($this->tokens[$i+$c+1]) 
											&& in_array($this->tokens[$i+$c+1][0], Tokens::$TOKEN_ARITHMETIC)) || $inSecuring )		
											{
												$secured_by_start = true;
												$isSecure = true;
											}
			
											if($inSecuring && !$ignoreSecuring)
												$this->securedby[] = $securing_function;
			
											// trace back parameters and look for userinput, trace constants globally
											$userInput = $this->scan_parameter(
												$new_find, 
												$new_find, 
												$this->tokens[$i+$c], 
												$this->tokens[$i+$c][3],
												$i+$c,
												($this->in_function && $this->tokens[$i + $c][1][0] === '$') ? $this->var_declares_local : $this->var_declares_global, 
												$this->var_declares_global,  
												false, 
												$this->scan_functions[$tokenValue][1], 
												false, // no return-scan
												$ignoreSecuring, 
												($isSecure || $inSecuring)
											);										

											$reconstructstr.= StringAnalyzer::get_var_value(
												$this->file_pointer,
												$this->tokens[$i+$c], 
												($this->in_function && $this->tokens[$i + $c][1][0] === '$') ? $this->var_declares_local : $this->var_declares_global, 
												$this->var_declares_global, 
												$i+$c,
												$this->source_functions
											);	
											
											
											if($userInput /*&& (!$isSecure || $GLOBALS['verbosity'] == 3)*/ )
											{
												$vulnparams[] = $parameter;
												if($userInput == 1)
													$parameter_has_userinput = true;
												else if($userInput == 2)
													$parameter_func_depend = true;
												$taintedVars[] = $var_counter;
											} 
										} 
										
										// mark userinput for quote analysis
										if(in_array($this->tokens[$i + $c][1], Sources::$SRC_USERINPUT))
										{
											$reconstructstr.='$_USERINPUT';
										}
									}
									// userinput from return value of a function
									else if( $this->tokens[$i + $c][0] === T_STRING 
									&& in_array($this->tokens[$i + $c][1], $this->source_functions) 
									// scan only potential vulnerable parameters of function call
									&& ( in_array($parameter, $this->scan_functions[$tokenValue][0]) 
									|| (isset($this->scan_functions[$tokenValue][0][0])
									&& $this->scan_functions[$tokenValue][0][0] === 0) ) )// all parameters accepted
									{	
										$has_vuln_parameters = true;
										$parameter_has_userinput = true;
										$new_find->marker = 1; 
										$reconstructstr.='$_USERINPUT';
										$new_find->title = 'A1736 - Userinput returned by function <i>'.$this->tokens[$i + $c][1].'</i> reaches sensitive sink';
										$this->add_trigger_function($new_find);
									}	
									//detect insecuring functions (functions that make previous securing useless)
									else if( $this->tokens[$i + $c][0] === T_STRING 
									&& isset($this->tokens[$i+$c][1]) && in_array($this->tokens[$i+$c][1], $GLOBALS['F_INSECURING_STRING']) 
									&& $parenthesesSaveState == -1)
									{
										$parenthesesSaveState = $parenthesesIsOpen;
										$ignoreSecuring = true;
									}
									// detect securing functions embedded into the sensitive sink
									else if( !$ignoreSecuring && ($this->tokens[$i + $c][0] === T_STRING 
									&& ( (is_array($this->scan_functions[$tokenValue][1]) 
									&& in_array($this->tokens[$i+$c][1], $this->scan_functions[$tokenValue][1]))
									|| in_array($this->tokens[$i+$c][1], $GLOBALS['F_SECURING_STRING']) ) ) 
									|| (in_array($this->tokens[$i+$c][0], Tokens::$TOKEN_CASTS) && $this->tokens[$i+$c+1] === '('))
									{
										$securing_function = $this->tokens[$i+$c][1];
										$parenthesesSaveState = $parenthesesIsOpen;
										$inSecuring = true;
										$secured_by_start = true;
									}
									// add strings to reconstructed string for quotes analysis
									else if( $this->tokens[$i + $c][0] === T_CONSTANT_ENCAPSED_STRING )
									{
										$reconstructstr.= substr($this->tokens[$i + $c][1], 1, -1);
									}
									else if( $this->tokens[$i + $c][0] === T_ENCAPSED_AND_WHITESPACE )
									{
										$reconstructstr.= $this->tokens[$i + $c][1];
									}
								}	
								// count parameters
								else if( $parenthesesIsOpen === 1 && $this->tokens[$i + $c] === ',' )
								{
									$parameter++;
								}
								// watch function calls in function call
								else if( $this->tokens[$i + $c] === '(' )
								{
									$parenthesesIsOpen++;
								}
								else if( $this->tokens[$i + $c] === ')' )
								{
									$parenthesesIsOpen--;
									if($parenthesesIsOpen === $parenthesesSaveState)
									{
										$parenthesesSaveState = -1;
										$inSecuring = false;
										$securing_function = '';
										$ignoreSecuring = false;
									}	
								}
								else if(!isset($this->tokens[$i+$c]))
								{
									add_error('Syntax error !!! (GR2231) ');
									break;	
								}
								$c++;
							}	
							
							// quote analysis for securing functions F_QUOTE_ANALYSIS
							// they only protect when return value is embedded into quotes
							if( $this->quote_analysis_needed() && substr_count($reconstructstr, '$_USERINPUT')  > 0 )
							{
								// idea: explode on $_USERINPUT and count quotes in SQL query before
								// if not even, then the $_USERINPUT is in an open quote
								$parts = explode('$_USERINPUT', $reconstructstr);
								foreach($this->securedby as $var=>$securefunction)
								{
									if(in_array($securefunction, $GLOBALS['F_QUOTE_ANALYSIS']))
									{
										// extract the string before the userinput
										$checkstring = '';
										$d=1;
										foreach($parts as $part)
										{
											$checkstring.=$part;
											if($d>=$var)
												break;
											$d++;	
										}

										// even amount of quotes (or none) in string 
										// --> no quotes around userinput
										// --> securing function is	useless
										if(substr_count($checkstring, "'") % 2 === 0
										&& substr_count($checkstring, '"') % 2 === 0)
										{
											$has_vuln_parameters = true;
											$parameter_has_userinput = true;
											$new_find->title .= "Userinput reaches sensitive sink due to insecure usage of $securefunction() without quotes";
										}
									}
								}
							}
							
							// add find to output if function call has variable parameters (With userinput)
							$parameter_func_depend = false;
							if( ($has_vuln_parameters && ($parameter_has_userinput || $parameter_func_depend)) || $GLOBALS['verbosity'] == 4 || isset($this->scan_functions[$tokenValue][3]) ) 
							{
								
								$vulnstart=$i;
								$vulnadd=1;
								// prepend $var assignment
								if(isset($vardeclare))
								{
									$vulnstart = $vardeclare['start'];
									$vulnadd = $vardeclare['end']-$vardeclare['start']-$c+1;//3;
								}	
								// prepend echo statement
								else if(isset($GLOBALS['F_XSS'][$this->tokens[$i-1][1]]))
								{
									$vulnstart = $i-1;
									$vulnadd = 2;
								}	
								// prepend class var
								else if($this->tokens[$i-1][0] === T_DOUBLE_COLON || $this->tokens[$i-1][0] === T_OBJECTOKEN_OPERATOR)
								{
									$vulnstart = $i-2;
									$vulnadd = 2;
								}
							
								if(isset($GLOBALS['user_functions'][$this->file_name][$tokenValue]))
								{
									$found_line = '<A NAME="'.$tokenValue.'_call" class="jumplink"></A>';
									$found_line.= highlightline(array_slice($this->tokens,$vulnstart,$c+$vulnadd),$this->comment, $lineNr, false, $tokenValue);
								} else
								{
									$found_line = highlightline(array_slice($this->tokens,$vulnstart,$c+$vulnadd),$this->comment, $lineNr, $tokenValue, false, $taintedVars);
								}
								
								$new_find->value = $found_line;
								$new_find->filename = $this->file_pointer;
							
								if($secured_by_start)
									$new_find->marker = 2; 

								// only show vuln user defined functions 
								// if call with userinput has been found
								if( isset($GLOBALS['user_functions'][$this->file_name][$tokenValue]) )
									$GLOBALS['user_functions'][$this->file_name][$tokenValue]['called'] = true;
								
								if($this->in_function)
								{
									$this->ignore_securing_function = true;
									// mark function in class as vuln
									if($this->in_class)
									{
										$this->vuln_classes[$this->class_name][] = $this->function_obj->name;
									}						
								}
								
								// putenv with userinput --> getenv is treated as userinput
								if($tokenValue === 'putenv')
								{
									$this->source_functions[] = 'getenv';
									$GLOBALS['source_functions'][] = 'getenv';
									$new_find->title = 'User can set PHP enviroment variables. Adding getenv() to tainting functions';
								}
								else if($tokenValue === 'apache_setenv')
								{
									$this->source_functions[] = 'apache_getenv';
									$GLOBALS['source_functions'][] = 'apache_getenv';
									$new_find->title = 'User can set Apache enviroment variables. Adding apache_getenv() to tainting functions';
								}
								else if($tokenValue === 'extract' || $tokenValue === 'parse_str' || $tokenValue === 'mb_parse_str')
								{
									// add register_globals implementation
									$this->variable_add(
										'register_globals', 
										array_slice($this->tokens,$vulnstart,$c+$vulnadd), 
										'register_globals implementation', 
										0, 0, 
										$lineNr, 
										$i, 
										isset($this->tokens[$i][3]) ? $this->tokens[$i][3] : array()
									);							
								}
							
								// add to output							
								if(isset($GLOBALS['user_functions'][$this->file_name][$tokenValue]))
								{										
									if(!empty($GLOBALS['output'][$this->file_name]))
									{
										foreach($GLOBALS['output'][$this->file_name] as $block)
										{
											$calleesadded = array();
											foreach($block->treenodes as $tree)
											{
												if($tree->funcdepend === $tokenValue 
												&& (array_intersect($tree->funcparamdepend, $vulnparams) || isset($this->scan_functions[$tokenValue][3]) ))
												{
													// if funcdependend already found and added, just add foundcallee=true and continue
													// dont add tree again, it is already added to the vulnblock
													if(in_array($tree->funcdepend, $calleesadded))
													{
														$tree->foundcallee = true;
														continue;
													}
												
													if(isset($this->scan_functions[$tokenValue][3]))
														$new_find->title = 'Call triggers vulnerability in function <i>'.$tokenValue.'()</i>';
													else if(empty($new_find->title))
														$new_find->title = 'Userinput is passed through function parameters.';
														
													$block->treenodes[] = $new_find;
													if(!$block->vuln && ($parameter_has_userinput || isset($this->scan_functions[$tokenValue][3]) || $GLOBALS['verbosity'] == 4))
													{
														$block->vuln = true;
														increaseVulnCounter($block->sink);
													}	
													
													$tree->foundcallee = true;
													$calleesadded[] = $tokenValue;
												}
											}
										}
										// else: dont use the result
									}
								} else
								{
									if(empty($new_find->title)) {
										$new_find->title = 'Found suspicious behavior';
									}
									$block = new VulnBlock($this->tif.'_'.$this->tokens[$i][2].'_'.basename($this->file_pointer), getVulnNodeTitle($tokenValue), $tokenValue);
									$block->treenodes[] = $new_find;
									if($parameter_has_userinput || $GLOBALS['verbosity'] == 4)
									{
										$block->vuln = true;
										increaseVulnCounter($tokenValue);
									}	
									// if sink in var declare, offer a data leak scan - save infos for that
									if(isset($vardeclare))
										$block->dataleakvar = array($vardeclare['linenr'], $vardeclare['name']);

									$GLOBALS['output'][$this->file_name][] = $block;
								}
								
							}

							// if classvar depends on function parameter, add this parameter to list
							if( isset($this->classvar) && $this->in_function && in_array($this->classvar, $this->function_obj->parameters) ) 
							{
								$param = array_search($this->classvar, $this->function_obj->parameters);
								$GLOBALS['user_functions'][$this->file_name][$this->function_obj->name][0][$param] = $param+1;
							} 
						
						} 
					} // taint analysis		
				}	

				// --- [ Control Structures ] ------------------------------------------

				else if( in_array($tokenName, Tokens::$TOKEN_LOOPCONTROL) ) 
				{
					// ignore in requirements output: while, for, foreach	
					// DO..WHILE was rewritten to WHILE in tokenizer
					$this->ignore_requirement = true; 
					
					$c=1;
					// get variables in loop condition
					while($this->tokens[$i+$c] !== '{')
					{
						if($this->tokens[$i+$c][0] === T_VARIABLE)
						{
							$this->tokens[$i+$c][3][] = '*';
						} 
						else if(!isset($this->tokens[$i+$c]))
						{
							add_error('Syntax error !!! (GR9920)');
							break;	
						}
						$c++;
					}
				}
				// save current dependency
				else if(in_array($tokenName, Tokens::$TOKEN_FLOWCONTROL))
				{
					$c=1;
					while($this->tokens[$i+$c] !== '{')
					{
						$c++;
						if(!isset($this->tokens[$i+$c]))
						{
							add_error('Syntax error !!! (GR9929)');
							break;	
						}
					}
					$this->in_condition = $i+$c;
					$this->dependencytokens = array_slice($this->tokens,$i,$c);
				}
				
				// --- [ T_FUNCTION ] ------------------------------------------
				else if($tokenName === T_FUNCTION)
				{
					if($this->in_function)
					{
						#add_error('New function declaration in function declaration of '.$this->function_obj->name.'() found. This is valid PHP syntax but not supported by RIPS now.', array_slice($this->tokens, $i, 10), $this->tokens[$i][2], $this->file_pointer);
					}	
					else
					{
						$this->in_function++;
					
						// the next token is the "function name()"
						$i++;
						$function_name = isset($this->tokens[$i][1]) ? $this->tokens[$i][1] : $this->tokens[$i+1][1];
						$ref_name = ($this->in_class ? $this->class_name.'::' : '') . $function_name;
											
						// add POP gadgets to info
						/* TODO remove
						if(isset($this->info_functions[$function_name]))
						{
							$GLOBALS['info'][] = $ref_name;
							
							// add gadget to output
							$found_line = highlightline(array_slice($this->tokens,$i-1,4),$this->comment, 
														$lineNr, $function_name, false, $function_name);
							$new_find = new InfoTreeNode($found_line);
							$new_find->title = "POP gadget $ref_name"; 
							$new_find->lines[] = $lineNr;
							$new_find->filename = $this->file_pointer;
			
							if(isset($GLOBALS['output'][$this->file_name]['gadgets']))
								$GLOBALS['output'][$this->file_name]['gadgets']->treenodes[] = $new_find;
							else
							{
								$block = new VulnBlock($this->tif.'_'.$this->tokens[$i][2].'_'.basename($this->file_pointer), 'POP gadgets');
								$block->vuln = true;
								$block->treenodes[] = $new_find;
								$GLOBALS['output'][$this->file_name]['gadgets'] = $block;
							}
								
						} 
						*/
						
						$c=3;
						while($this->tokens[$i+$c] !== '{' && $this->tokens[$i+$c] !== ';')
						{
							$c++;
						}
						
						// abstract functions ended
						if($this->tokens[$i+$c] === ';')
							$this->in_function--;

						// write to user_functions offset list for referencing in output
						$GLOBALS['user_functions_offset'][$ref_name][0] = $this->file_pointer;
						$GLOBALS['user_functions_offset'][$ref_name][1] = $lineNr-1;
						// save function as object
						$this->function_obj = new FunctionDeclare($this->dependencytokens = array_slice($this->tokens,$i-1,$c+1));
						$this->function_obj->lines[] = $lineNr; 
						$this->function_obj->name = $function_name;

						// save all function parameters
						$this->function_obj->parameters = array();
						$e=1;
						// until function test(...) {
						//  OR
						// interface test { public function test(...); }
						while( $this->tokens[$i+$e] !== '{' && $this->tokens[$i+$e] !== ';' )
						{	
							if( is_array($this->tokens[$i + $e]) && $this->tokens[$i + $e][0] === T_VARIABLE )
							{
								$this->function_obj->parameters[] = $this->tokens[$i + $e][1];
							}
							$e++;
						}
						// now skip the params from rest of scan,
						// or function test($a=false, $b=false) will be detected as var declaration
						$i+=$e-1; // -1, because '{' must be evaluated again
					}
				}
				// add globaled variables (global $a, $b, $c;) to var list	
				else if($tokenName === T_GLOBAL && $this->in_function)
				{
					$this->globals_from_function[$this->function_obj->name] = array();
					
					// get all globaled variables 
					$b=1;
					while($this->tokens[$i + $b] !== ';')
					{
						if( $this->tokens[$i + $b][0] === T_VARIABLE )
						{
							// mark variable as global scope affecting
							$this->put_in_global_scope[] = $this->tokens[$i+$b][1];
							// add variable declaration to beginning of varlist
							$new_var = new VarDeclare(array(
								array(T_GLOBAL,'global',$lineNr),
								array(T_VARIABLE,$this->tokens[$i+$b][1],$lineNr),
								';'
							), $this->comment);
							$new_var->line = $lineNr;
							$new_var->id = $i;
							
							// overwrite old local vars
							$this->var_declares_local[$this->tokens[$i+$b][1]] = array($new_var);
						}
						$b++;
					}
				}				
				// watch returns before vuln function gets called
				else if($tokenName === T_RETURN && $this->in_function==1 )
				{
					$GLOBALS['userfunction_taints'] = false;
					$GLOBALS['userfunction_secures'] = false;
					$c = 1;
					// get all variables in parameter list
					while( $this->tokens[$i + $c] !== ';' )
					{
						if( is_array($this->tokens[$i + $c]) )
						{
							if( $this->tokens[$i + $c][0] === T_VARIABLE )
							{
								// check if returned var is secured --> securing function
								$new_find = new VulnTreeNode();
								$userInput = $this->scan_parameter(
									$new_find, 
									$new_find, 
									$this->tokens[$i+$c], 
									$this->tokens[$i+$c][3],
									$i+$c,
									$this->var_declares_local,  
									$this->var_declares_global,									
									false, 
									$GLOBALS['F_SECURES_ALL'], 
									TRUE
								);
									
								// add function to securing functions 
								// if it returns no userinput/function param
								if((!$userInput || $GLOBALS['userfunction_secures']) && !$this->ignore_securing_function)
								{
									$GLOBALS['F_SECURING_STRING'][] = $this->function_obj->name;
								}
								
								// add function to userinput functions if userinput
								// is fetched in the function and then returned (userinput == 1)
								if($userInput == 1 || $GLOBALS['userfunction_taints'])
								{
									$this->source_functions[] = $this->function_obj->name;
								}
							}
							// add function to securing functions if return value is secured
							else if( in_array($this->tokens[$i + $c][1], $GLOBALS['F_SECURES_ALL']) 
							|| in_array($this->tokens[$i+$c][0], Tokens::$TOKEN_CASTS))
							{
								$GLOBALS['F_SECURING_STRING'][] = $this->function_obj->name;
								break;
							}
						}
						$c++;
					}
				}				
				
				// --- [ T_CLASS ] ------------------------------------------

				// check if token is a class declaration
				else if($tokenName === T_CLASS)
				{
					$i++;
					$this->class_name = $this->tokens[$i][1];
					$this->vuln_classes[$this->class_name] = array();
					$this->in_class = true;
					$GLOBALS['info'][] = '<font color="red">Code is object-oriented. This is not supported yet and can lead to false negatives.</font>';
				}
				// build list of vars that are associated with a class
				// $var = new Classname()
				else if( $tokenName === T_NEW && $this->tokens[$i-2][0] === T_VARIABLE )
				{
					$this->class_vars[ $this->tokens[$i-2][1] ] = $this->tokens[$i+1][1];
				}
				// copy vuln functions from extended classes
				else if($tokenName === T_EXTENDS && $this->in_class)
				{
					$this->vuln_classes[$this->class_name] = $this->vuln_classes[ $this->tokens[$i+1][1] ];
				}
				
				
				// --- [ OTHERS ] ------------------------------------------
				
				// list($drink, $color, $power) = $info;
				else if($tokenName === T_LIST)
				{		
					$d=2;
					while( $this->tokens[$i+$d] !== ')' && $this->tokens[$i+$d] !== ';')
					{
						$d++;
						if($this->tokens[$i+$d] === ';' || !isset($this->tokens[$i+$d]))
						{
							add_error('Syntax error !!! (GR2929)');
							break;	
						}
					}
					$tokenscanstart = 0;
					if($this->tokens[$i+$d+1] === '=' || in_array($this->tokens[$i+$d+1][0], Tokens::$TOKEN_ASSIGNMENT))
						$tokenscanstart = $d+1;
					$c=2;
					for($c=2;$c<$d;$c++)
					{
						if( is_array($this->tokens[$i + $c]) 
						&& $this->tokens[$i + $c][0] === T_VARIABLE )
						{
							$this->variable_add(
								$this->tokens[$i + $c][1], 
								array_slice($this->tokens,$i,StringAnalyzer::getBraceEnd($this->tokens,$i)+1), 
								' list() ', 
								$tokenscanstart, 0, 
								$this->tokens[$i + $c][2],
								$i, 
								isset($this->tokens[$i+$c][3]) ? $this->tokens[$i+$c][3] : array()
							);
						}
					}	
					$i=$i+$c+2;
				}				
				// switch lines pointer back to original code if included tokens end
				else if( $tokenName === T_INCLUDE_END)
				{
					array_pop($this->lines_stack);
					$this->lines_pointer = end($this->lines_stack);	
					array_pop($this->inc_file_stack);
					$this->file_pointer = end($this->inc_file_stack);
					$this->comment = basename($this->file_pointer) == basename($this->file_name) ? '' : basename($this->file_pointer);
					$this->tif = array_pop($this->tif_stack);
				}					
				
			} else // token is not an array
			{
				/*************************
						BRACES		
				*************************/
				// keep track of { program blocks }
				// get current dependencies in program flow
				if($this->tokens[$i] === '{' 
				&& ($this->tokens[$i-1] === ')' || $this->tokens[$i-1] === ':' || $this->tokens[$i-1] === ';' // case x:{ or case x;{ 
				|| (is_array($this->tokens[$i-1])
				&& ($this->tokens[$i-1][0] === T_DO  // do {
				|| $this->tokens[$i-1][0] === T_ELSE // else {
				|| $this->tokens[$i-1][0] === T_STRING // class bla {
				|| $this->tokens[$i-1][0] === T_TRY // try {
				|| $this->tokens[$i-1][0] === T_CATCH)) ) ) // catch{
				{
					// save brace amount at start of function
					if($this->in_function && $this->brace_save_func < 0) 
					{
						$this->brace_save_func = $this->braces_open;
					}	
					
					// save brace amount at start of class
					if($this->in_class && $this->brace_save_class < 0)
					{
						$this->brace_save_class = $this->braces_open;
					}
					
					$this->in_condition = 0;

					if(empty($e))
					{					
						if(!$this->ignore_requirement)
						{
							if(!empty($this->dependencytokens) 
							&& $this->dependencytokens[0][0] === T_ELSE && $this->dependencytokens[1][0] !== T_IF ) 
							{
								$this->dependencytokens = $this->last_dependency;
								$this->dependencytokens[] = array(T_ELSE, 'else', $this->dependencytokens[0][2]);
							}	
						} else
						{
							$this->ignore_requirement = false;
						}
					
						// add dependency (even push empty dependency on stack, it will get poped again)
						$this->dependencies[$lineNr] = $this->dependencytokens;	
						$this->dependencytokens = array();						
					} else
					{
						unset($e);
					}
					
					$this->braces_open++;
				}	
				// before block ending "}" there must be a ";" or another "}". otherwise curly syntax
				else if( $this->tokens[$i] === '}' 
				&& ($this->tokens[$i-1] === ';' || $this->tokens[$i-1] === '}' || $this->tokens[$i-1] === '{') )
				{
					$this->braces_open--;
					
					// delete current dependency
					$this->last_dependency = array_pop($this->dependencies);
					$this->dependencytokens = array();

					// end of function found if brace amount = amount before function start
					if($this->in_function && $this->brace_save_func === $this->braces_open)
					{
						$ref_name = ($this->in_class ? $this->class_name.'::' : '') . $this->function_obj->name;
						// write ending to user_function list for referencing functions in output
						$GLOBALS['user_functions_offset'][$ref_name][2] = $lineNr;
						// reset vars for next function declaration
						$this->brace_save_func = -1;
						$this->ignore_securing_function = false;
						$this->in_function--;
						$this->function_obj = null;
						$this->var_declares_local = array();
						$this->put_in_global_scope = array();
						// load new found vulnerable user functions to current scanlist
						if(isset($GLOBALS['user_functions'][$this->file_name]))
						{
							$this->scan_functions = array_merge($this->scan_functions, $GLOBALS['user_functions'][$this->file_name]);
						}
					} 
					
					// end of class found
					if($this->in_class && $this->brace_save_class === $this->braces_open)
					{
						$this->brace_save_class = -1;
						$this->in_class = false;
					}
				}
			} // token scanned
			
			// detect if still in a vardeclare, otherwise delete saved infos
			if(isset($vardeclare) && $vardeclare['end'] === $i)
				unset($vardeclare);

		} // all tokens scanned.		
		return $this->inc_map;
	}
}	
?>	
