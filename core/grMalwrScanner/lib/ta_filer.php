<?php

	// get all php files from directory, including all subdirectories
	function read_recursiv($path)
	{  
		$result = array(); 

		$handle = opendir($path);  
		
		if ($handle)  
		{  
			while (false !== ($file = readdir($handle)))  
			{  
				if ($file !== '.' && $file !== '..')  
				{  
					$name = $path . '/' . $file; 
					if (is_dir($name)) 
					{  
						$ar = read_recursiv($name, true); 
						foreach ($ar as $value) 
						{ 
							if(in_array(substr($value, strrpos($value, '.')), $GLOBALS['FILETYPES']))
								$result[] = $value; 
						} 
					} else if(in_array(substr($name, strrpos($name, '.')), $GLOBALS['FILETYPES'])) 
					{  
						$result[] = $name; 
					}  
				}  
			}  
		}  
		closedir($handle); 
		return $result;  
	}  
	
?>	