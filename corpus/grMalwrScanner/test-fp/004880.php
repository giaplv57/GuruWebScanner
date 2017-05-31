<?php

/* -------------------------------------------------------------
----------------------------------------------------------------
|                                                              |
|  File name : markup.class.php                                |
|  Usage     : Generating form elements (markup)               |
|  Class     : BhittaniPlugin_AdminMarkup                      |
|  Version   : 0.1                                             |
|  Author    : Kamal Khan                                      |
|  URI       : http://wp.bhittani.com/framework                |
|                                                              |
|  Description :                                               |
|  Holds the markup for different form elements mainly used in |
|  the settings page                                           |
|                                                              |
|  -CHANGELOG-                                                 |
|  ----------------------------------------------------------  |
|  0.1 - First release                                         |
|                                                              |
----------------------------------------------------------------
------------------------------------------------------------- */

if(!class_exists('BhittaniPlugin_AdminMarkup')) :

    // Declare and define the class.
	class BhittaniPlugin_AdminMarkup
	{
		private static function _finish($html, $echo)
		{
			if(!$echo)
			{
				return $html;
			}
			echo $html;
			return true;
		}
		private static function _prepend($title='', $description='', $html='')
		{
		    $html .= '<div class="bf_box">';
			$html .= !empty($description) ? ('	<div class="bf_aside">' . $description . '</div>') : '';
			$html .= !empty($title) ? ('	<h4>' . $title . '</h4>') : '';
			return $html;
		}
		private static function _append($html)
		{
		    $html .= '</div>';	
			return $html;
		}
		private static function _element($title='', $description='', $markup='', $echo)
		{
			$html = self::_prepend($title, $description);
			$html .= $markup;
			$html = self::_append($html);
			return self::_finish($html, $echo);
		}
		public static function html($html, $_echo = true)
		{
			return self::_element('', '', $html, $_echo);
		}
		public static function input($_attr, $_echo = true)
		{
			extract($_attr);
			
			$_html = '<input type="text" name="'.$field.'" class="'.(isset($class)?$class:'').'" value="'.(isset($value)?$value:'').'" placeholder="'.(isset($placeholder)?$placeholder:'').'" />';
			
			return self::_element($title, $description, $_html, $_echo);
		}
		public static function textarea($_attr, $_echo = true)
		{
			extract($_attr);
			
			$_html = '<textarea name="'.$field.'" class="'.(isset($class)?$class:'').'">'.(isset($value)?$value:'').'</textarea>';
			
			return self::_element($title, $description, $_html, $_echo);
		}
		public static function select($_attr, $_echo = true)
		{
			extract($_attr);
			
			$_html = '<select name="'.$field.'" class="'.(isset($class)?$class:'').'">';
            foreach($options as $option)
			{
				if(!is_array($option))
				    $option = array($option);
				$_html .= '<option value="'.$option[0].'"'.(isset($value)&&($value==$option[0])?' selected="selected"':'').'>'.(isset($option[1])?$option[1]:$option[0]).'</option>';
			}
            $_html .= '</select>';
			
			return self::_element($title, $description, $_html, $_echo);
		}
		public static function checkbox($_attr, $_echo = true)
		{
			extract($_attr);
			$_html = '';
			if(is_array($obj))
			{
				foreach($obj as $O)
				{
					extract($O);
					$_html .= '<div'.(isset($pclass)?(' class="'.$pclass.'"'):'').'>';
		            $_html .= '    <input type="text" name="'.$field.'" class="chkbox '.(isset($value)&&$value?'_on':'_off').' modern allow-click bf__checkbox '.(isset($class)?$class:'').'" value="'.(isset($value)?$value:'0').'" />';
		            $_html .= '    <span class="bf-label allow-click">'.$label.'</span>';
		            $_html .= '</div>';
				}
			}
			
			return self::_element($title, $description, $_html, $_echo);
		}
		public static function color($_attr, $_echo = true)
		{
			extract($_attr);
			
			$_html = '<div'.(isset($pclass)?(' class="'.$pclass.'"'):'').'>';
            $_html .= '    <input type="text" name="'.$field.'" class="color modern allow-click bf__color '.(isset($class)?$class:'').'" value="'.(isset($value)?$value:'#FFFFFF').'" style="background-color:'.(isset($value)?$value:'#FFFFFF').';" />';
            $_html .= '    <span class="bf-label allow-click">'.$label.'</span>';
            $_html .= '</div>';
			
			return self::_element($title, $description, $_html, $_echo);
		}
		public static function image($_attr, $_echo = true)
		{
			extract($_attr);
			
            $_html = '<div class="bf-image bf__img_preview">';
			$_html .= '	<img src="'.(isset($value)&&$value?$value:'').'" title="'.$caption.'" alt="'.$caption.'" />';
			$_html .= '	<a href="#" class="bf-remove bf__img_remove" rel="'.$field.'" title="Remove"></a>';
			$_html .= '	<input type="hidden" name="'.$field.'" value="'.$value.'" alt="Use as '.$caption.'" />';
			$_html .= '	<input type="button" value="Select Image" class="button __imageuploadid" />';
			$_html .= '</div>';
			
			return self::_element($title, $description, $_html, $_echo);
		}
	}
	
endif;

?>