<?php

if(!class_exists('BhittaniPlugin_kkStarRatings_Shortcode')) : 
    // Declare and define the class.
	class BhittaniPlugin_kkStarRatings_Shortcode
	{	
		
		static public function tinymce_add_button()
		{
			if ( ! current_user_can('edit_posts') && ! current_user_can('edit_pages') )
				return;

			if ( get_user_option('rich_editing') == 'true') 
			{
				add_filter("mce_external_plugins", array("BhittaniPlugin_kkStarRatings_Shortcode","tinymce_custom_plugin"));
				add_filter('mce_buttons', array("BhittaniPlugin_kkStarRatings_Shortcode",'tinymce_register_button'));
			}
		}
			 
		static public function tinymce_register_button($buttons) 
		{
			array_push($buttons, "|", "kkstarratings");
			return $buttons;
		}
			 
		static public function tinymce_custom_plugin($plugin_array) 
		{
			//echo WP_PLUGIN_URL.'/kk-star-ratings/shortcode/mce/kkstarratings/editor_plugin.js';
			//$plugin_array['kkstarratings'] = WP_PLUGIN_URL.'/kk-star-ratings/shortcode/mce/kkstarratings/editor_plugin.js';
			$plugin_array['kkstarratings'] = BhittaniPlugin_kkStarRatings::file_uri('shortcode/mce/kkstarratings/editor_plugin.js');
			return $plugin_array;
		}
	}
	
	add_action('init', array('BhittaniPlugin_kkStarRatings_Shortcode','tinymce_add_button'));

endif;
?>