# Verboten

A lightning fast firewall that automatically protects your Wordpress site against malicious URL requests. Why this plugin name? Verboten means "forbidden" in German.

## Copyright and License

This project is licensed under the [GNU GPL](http://www.gnu.org/licenses/old-licenses/gpl-2.0.html), version 2 or later.

## Documentation

Verboten has no configuration or settings screen because configuration isn't necessary. It uses blacklist rules based on <a href="https://perishablepress.com/7g-firewall/" target="_blank">7G Firewall</a>. 

This plugin provides an API to to customise the default values for hostile request uris, query strings, user agents and referrers. See these examples:

	// ---- Change the Verboten plugin hostile request uris array.
	add_filter('verboten_request_uris', 'custom_verboten_request_uris_filter');
	function custom_verboten_request_uris_filter($array) {
		if (empty($_REQUEST['wc-api']) == false) {
			return array(); // Don't trigger error for Woocommerce API transactions
		}
		return $array;
	}

	// ---- Change the Verboten plugin hostile query strings array.
	add_filter('verboten_query_strings', 'custom_verboten_query_strings_filter');
	function custom_verboten_query_strings_filter($array) {
		if (empty($_REQUEST['wc-api']) == false) {
			return array(); // Don't trigger error for Woocommerce API transactions
		}
		return $array;
	}

	// ---- Change the Verboten plugin hostile user agents array.
	add_filter('verboten_user_agents', 'custom_verboten_user_agents_filter');
	function custom_verboten_user_agents_filter($array) {
		return $array;
	}

	// ---- Change the Verboten plugin hostile referrers array.
	add_filter('verboten_referrers', 'custom_verboten_referrers_filter');
	function custom_verboten_referrers_filter($array) {
		return $array;
	}

	// ---- Change the Verboten plugin hostile remote hosts array.
	add_filter('verboten_remote_hosts', 'custom_verboten_remote_hosts_filter');
	function custom_verboten_remote_hosts_filter($array) {
		return $array;
	}

	// ---- Change the Verboten plugin hostile request methods array.
	add_filter('verboten_request_methods', 'custom_verboten_request_methods_filter');
	function custom_verboten_request_methods_filter($array) {
		return $array;
	}


You could also implement an access denial logging mechanism. See these examples:

	// ---- Log debug info for Verboten access errors.
	// ---- Status can be (1) QUERY_STRING (2) REQUEST_URI (4) HTTP_USER_AGENT (8) HTTP_REFERER (16) REMOTE_HOST (32) REQUEST_METHOD
	add_action('verboten_debug', 'custom_verboten_debug_action');
	function custom_verboten_debug_action($status) {
		$verboten = array('status' => $status, 'data' => array());
		foreach (array('QUERY_STRING', 'REQUEST_URI', 'HTTP_USER_AGENT', 'HTTP_REFERER', 'REMOTE_ADDR', 'REMOTE_HOST', 'REQUEST_METHOD') as $key) {
			if (isset($_SERVER[$key]) == true) {
				$verboten['data'][$key] = $_SERVER[$key];
			}
		}
		custom_verboten_logfile(json_encode($verboten), 'verboten');
	}

	// ---- Verboten debug logging.
	function custom_verboten_logfile($data, $label = 'var') {
		$path = sprintf('%s/verboten-%s.log', WP_CONTENT_DIR, hash('adler32', sprintf('%s|%s|%s', AUTH_KEY, AUTH_COOKIE, AUTH_SALT)));
		if ($fp = fopen($path, 'a')) {
			if (is_array($data) || is_object($data)) {
				$data = print_r($data, true);
			}
			fwrite($fp, sprintf("[%s] %s: %s\n", date_i18n('Y-m-d H:i:s', time() + (get_option('gmt_offset') * HOUR_IN_SECONDS)), $label, $data));
			fclose($fp);
		}
	}

## Professional Support

If you need professional plugin support from me, the plugin author, contact me via my website at http://lutrov.com
