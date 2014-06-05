<?php

/*
  Plugin Name: NGINX Secure Media
  Plugin URI: http://voceplatforms.com
  Description: Adds a security token and expiration to media uploads which can be used in conjuction with Nginx's http_secure_link_module to limit unauthenticated access.
  Version: 0.1.2
  Author: Michael Pretty, Voce Platforms
  License: GPL2
 */

class NGINX_Secure_Media {

	protected $secret;
	protected $expiry;

	/**
	 * 
	 */
	public function setup() {
		@include(__DIR__ . '/vendor/autoload.php');
		$voce_settings_api = Voce_Settings_API::GetInstance();
		if ( is_admin() ) {
			$voce_settings_api->add_page( 'Secure Media', 'Secure Media', 'nginx-secure-media', 'manage_options', '', 'options-general.php' )
				->add_group( 'Settings', 'http_secure_link' )
				//->add_setting( 'Secret Key', 'secret', array( 'description' => 'Secret word shared with NGINX for creating the hash.' ) )->group
				->add_setting( 'Expire Time', 'expiry', array( 'description' => 'Minimum time in seconds that a link should be valid.  If you have output caching on, this should be greater than the time set for output caching.', 'sanitize_callbacks' => array( 'vs_sanitize_int' ) ) );
		}
		if ( defined( 'HTTP_SECURE_LINK_SECRET' ) ) {
			$this->secret = HTTP_SECURE_LINK_SECRET;
			$expiry = $voce_settings_api->get_setting( 'secret', 'http_secure_link' );
			$this->expiry = $expiry > 30 ? $expiry : 30;
			$this->start_buffer();
		} elseif ( is_admin() && current_user_can( 'install_plugins' ) ) {
			add_action( 'admin_notices', array( $this, 'admin_notice' ) );
			if ( isset( $_GET['nsm_ignore_notice'] ) ) {
				update_user_meta( get_current_user_id(), 'nsm_ignore_notice', true );
			}
		}
	}

	public function admin_notice() {
		if ( !get_user_meta( get_current_user_id(), 'nsm_ignore_notice', true ) ) {
			printf( '<div class="updated"><p>%s. <a href="%s">Ignore this message.</a></p></div>', 'Setup for NGINX Secure Media will not be complete until <strong>HTTP_SECURE_LINK_SECRET</strong> is defined in your wp-config.php', add_query_arg( array( 'nsm_ignore_notice' => 1 ) ) );
		}
	}

	public function start_buffer() {
		ob_start( array( $this, 'filter_media_urls' ) );
	}

	public function filter_media_urls( $content ) {
		$dir_info = wp_upload_dir();
		$uploads_url = $dir_info['baseurl'];
		$site_url = untrailingslashit( get_site_url() );
		if ( false !== strpos( $content, $uploads_url, $site_url ) ) {
			$secret = $this->secret;
			$time = time();
			//to allow the slightest bit of browser caching, we'll round up to the next expiration block
			$expires = $time + $this->expiry + ( $this->expiry - ( $time % $this->expiry ) );
			$callback = function($matches) use ($secret, $expires, $site_url) {
					$path = substr( $matches[0], strlen( $site_url ) );
					$md5 = base64_encode( md5( $secret . $path . $expires, true ) );
					$md5 = str_replace( array( '+', '/', '=' ), array( '-', '_', '' ), $md5 );
					return $matches[0] . '?s=' . $md5 . '&e=' . $expires;
				};
			$regex = '/(' . preg_quote( $uploads_url, '/' ) . '[^\s\'"]*)/';
			$content = preg_replace_callback( $regex, $callback, $content );
		}
		return $content;
	}

}

add_action( 'wp_loaded', array( new NGINX_Secure_Media(), 'setup' ) );