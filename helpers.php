<?php

	// Security
	if (!defined('ABSPATH')) exit;


	//
	// API Methods
	//

	/**
	 * Check if request is not Ajax
	 * @return Boolean If true, is not Ajax
	 */
	function gmt_member_is_not_ajax () {
		return empty($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest';
	}

	/**
	 * Check if reset key has expired
	 * @param  Array   $reset_key The reset key array
	 * @return Boolean            If true, reset key has expired
	 */
	function gmt_member_has_reset_key_expired ($reset_key) {
		return !empty($reset_key['expires']) && time() > $reset_key['expires'];
	}

	/**
	 * Get the minimum password length
	 * @return Integer The minimum password length
	 */
	function gmt_member_get_pw_length () {
		$pw_length = getenv('MIN_PASSWORD_LENGTH');
		$pw_length = $pw_length ? intval($pw_length) : 8;
		return $pw_length;
	}

	/**
	 * Check if the password is too short
	 * @param  String  $pw        The password
	 * @param  Integer $pw_length The minimum length
	 * @return Boolean            If true, password is too short
	 */
	function gmt_member_is_pw_too_short ($pw, $pw_length) {
		return strlen($pw) < $pw_length;
	}


	//
	// Product Methods
	//

	/**
	 * Check if the user has an active subscription
	 * @param  string $email The user's email address
	 * @return boolean       If true, user has an active subscription
	 */
	function gmt_member_has_active_subscription ($email = '') {
		if (empty($email)) return false;
		$subscriber = new EDD_Recurring_Subscriber($email);
		return $subscriber->has_active_subscription();
	}


	/**
	 * Get summary of content
	 * @param  string $email The user's email address
	 * @return array         The summary of content
	 */
	function gmt_member_get_content_summary ($email = '') {
		return json_decode(file_get_contents(realpath(ABSPATH . DIRECTORY_SEPARATOR . '..') . '/index.json'), false);
	}


	/**
	 * Get content details
	 * @param  string $email The user's email address
	 * @return array         The content details
	 */
	function gmt_member_get_content_details ($email = '', $type = '', $api_dir = '') {

		// Ensure correct data provided
		if (empty($type) || empty($api_dir)) return;

		// Get content details
		return json_decode(file_get_contents(realpath(ABSPATH . DIRECTORY_SEPARATOR . '..') . '/' . trim($api_dir, '/') . '/index.json'), false);

	}



	//
	// Utilities
	//

	/**
	 * Get an encoded email link
	 * @return string The email link
	 */
	function gmt_member_get_email () {
		return '<a href="mailto:&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;">&#099;&#104;&#114;&#105;&#115;&#064;&#103;&#111;&#109;&#097;&#107;&#101;&#116;&#104;&#105;&#110;&#103;&#115;&#046;&#099;&#111;&#109;</a>';
	};


	/**
	 * Get the site domain and remove the www.
	 * @return string The site domain
	 */
	function gmt_member_get_site_domain() {
		$sitename = strtolower( $_SERVER['SERVER_NAME'] );
		if ( substr( $sitename, 0, 4 ) == 'www.' ) {
			$sitename = substr( $sitename, 4 );
		}
		return $sitename;
	}