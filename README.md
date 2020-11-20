# Verboten

A lightning fast firewall that automatically protects your Wordpress site against malicious URL requests. Why this plugin name? Verboten means "forbidden" in German.

## Copyright and License

This project is licensed under the [GNU GPL](http://www.gnu.org/licenses/old-licenses/gpl-2.0.html), version 2 or later.

## Documentation

Verboten has no configuration or settings screen because configuration isn't necessary. It uses blacklist rules based on <a href="https://perishablepress.com/7g/" target="_blank">7G Firewall</a>. 

This plugin provides an API to to customise the default values for hostile request uris, query strings and user agents. See these examples:

	// ---- Change the Verboten plugin hostile request uris array.
	add_filter('verboten_request_uris', 'custom_verboten_request_uris_filter');
	function custom_verboten_request_uris_filter($array) {
		return $array;
	}

	// ---- Change the Verboten plugin hostile query strings array.
	add_filter('verboten_query_strings', 'custom_verboten_query_strings_filter');
	function custom_verboten_query_strings_filter($array) {
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

## Professional Support

If you need professional plugin support from me, the plugin author, contact me via my website at http://lutrov.com
