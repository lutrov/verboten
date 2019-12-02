<?php

/*
Plugin Name: Verboten
Version: 2.2
Description: A lightning fast firewall that automatically protects your Wordpress site against malicious URL requests. No configuration necessary. Uses blacklist rules based on <a href="https://perishablepress.com/6g/" target="_blank">6G Firewall</a>. Why this plugin name? Verboten means "forbidden" in German.
Author: Ivan Lutrov
Author URI: http://lutrov.com/
*/

defined('ABSPATH') || die();

//
// Main action.
//
add_action('plugins_loaded', 'verboten', 10, 0);
function verboten() {
	$c = 0;
	if (empty($_SERVER['REQUEST_URI']) == false) {
		$hostile = implode('|', apply_filters('verboten_request_uri_filter',
			array('@eval', 'eval\(', 'UNION(.*)SELECT', '\(null\)', 'base64_', '\/localhost', '\%2Flocalhost', '\/pingserver', 'wp-config\.php', '\/config\.', '\/wwwroot', '\/makefile', 'crossdomain\.', 'proc\/self\/environ', 'usr\/bin\/perl', 'var\/lib\/php', 'etc\/passwd', '\/https\:', '\/http\:', '\/ftp\:', '\/file\:', '\/php\:', '\/cgi\/', '\.cgi', '\.cmd', '\.bat', '\.exe', '\.sql', '\.ini', '\.dll', '\.htacc', '\.htpas', '\.pass', '\.asp', '\.jsp', '\.bash', '\/\.git', '\/\.svn', ' ', '\<', '\>', '\/\=', '\.\.\.', '\+\+\+', '@@', '\/&&', '\/Nt\.', '\;Nt\.', '\=Nt\.', '\,Nt\.', '\.exec\(', '\)\.html\(', '\{x\.html\(', '\(function\(', '\.php\([0-9]+\)', '(benchmark|sleep)(\s|%20)*\(', 'indoxploi', 'xrumer')
		));
		if (empty($hostile) == false) {
			if (preg_match(sprintf('#%s#i', $hostile), $_SERVER['REQUEST_URI']) == 1) {
				$c++;
			}
		}
	}
	if (empty($_SERVER['QUERY_STRING']) == false) {
		$hostile = implode('|', apply_filters('verboten_query_string_filter',
			array('@@', '\(0x', '0x3c62723e', '\;\!--\=', '\(\)\}', '\:\;\}\;', '\.\.\/', '127\.0\.0\.1', 'UNION(.*)SELECT', '@eval', 'eval\(', 'base64_', 'localhost', 'loopback', '\%0A', '\%0D', '\%00', '\%2e\%2e', 'allow_url_include', 'auto_prepend_file', 'disable_functions', 'input_file', 'execute', 'file_get_contents', 'mosconfig', 'open_basedir', '(benchmark|sleep)(\s|%20)*\(', 'phpinfo\(', 'shell_exec\(', '\/wwwroot', '\/makefile', 'path\=\.', 'mod\=\.', 'wp-config\.php', '\/config\.', '\$_SESSION', '\$_REQUEST', '\$_ENV', '\$_SERVER', '\$_POST', '\$_GET', 'indoxploi', 'xrumer')
		));
		if (empty($hostile) == false) {
			if (preg_match(sprintf('#%s#i', $hostile), $_SERVER['QUERY_STRING']) == 1) {
				$c++;
			}
		}
	}
	if (empty($_SERVER['HTTP_USER_AGENT']) == false) {
		$hostile = implode('|', apply_filters('verboten_user_agent_filter',
			array('acapbot', '\/bin\/bash', 'binlar', 'casper', 'cmswor', 'diavol', 'dotbot', 'finder', 'flicky', 'md5sum', 'morfeus', 'nutch', 'planet', 'purebot', 'pycurl', 'semalt', 'shellshock', 'skygrid', 'snoopy', 'sucker', 'turnit', 'vikspi', 'zmeu')
		));
		if (empty($hostile) == false) {
			if (preg_match(sprintf('#%s#i', $hostile), $_SERVER['HTTP_USER_AGENT']) == 1) {
				$c++;
			}
		}
	}
	if ($c > 0) {
		header('HTTP/1.1 403 Forbidden');
		header('Status: 403 Forbidden');
		header('Connection: Close');
		if (file_exists(dirname(__FILE__) . '/403.php') == true) {
			load_plugin_textdomain('verboten', false, basename(dirname(__FILE__)) . '/lang/');
			include(dirname(__FILE__) . '/403.php');
		}
		exit();
	}	
}

?>
