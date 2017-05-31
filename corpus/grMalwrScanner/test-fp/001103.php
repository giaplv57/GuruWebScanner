<?php
/**
 * Handles iFrame request from tinyMCE button; saves login
 * @uses insert_story_dialog() or login_dialog()
 */
 
define( 'IFRAME_REQUEST' , true );

/** 
 *Load WordPress Administration Bootstrap 
 * Assume /wp-content/plugins/storify/
 */
require_once( '../../../wp-admin/admin.php' );

if ( 	!current_user_can( 'edit_posts' ) )
	wp_die( __("You are not allowed to be here") ); //native WP string, no need to i18n

@header('Content-Type: ' . get_option('html_type') . '; charset=' . get_option('blog_charset'));

wp_enqueue_script( 'tiny_mce_popup.js', includes_url( 'js/tinymce/tiny_mce_popup.js' ) );

global $WP_Storify;
if ( !$WP_Storify )
	$WP_Storify = WP_Storify::$instance;
	
if ( 	isset( $_POST['login'] ) 
		&& isset( $_POST['_wpnonce'] ) 
		&& wp_verify_nonce( $_POST['_wpnonce'], 'storify_login' ) 
	) {
	
	$login = apply_filters( 'storify_login', $_POST['login'] );
	
	if ( $login )
		update_user_option( get_current_user_id(), $WP_Storify->login_meta, $login );
	else
		delete_user_option( get_current_user_id(), $WP_Storify->login_meta );
	
}

$callback = ( $WP_Storify->get_login() ) ? 'insert_story_dialog' : 'login_dialog';

wp_iframe( array( &$WP_Storify, $callback ) ); 