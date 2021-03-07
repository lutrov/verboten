<?php

/*
Plugin Name: Verboten
Plugin URI: https://github.com/lutrov/verboten
Version: 3.0
Description: A lightning fast firewall that automatically protects your Wordpress site against malicious URL requests. No configuration necessary. Uses blacklist rules based on <a href="https://perishablepress.com/7g/" target="_blank">7G Firewall</a>. Why this plugin name? Verboten means "forbidden" in German.
Author: Ivan Lutrov
Author URI: http://lutrov.com/
Copyright: 2019, Ivan Lutrov

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
Street, Fifth Floor, Boston, MA 02110-1301, USA. Also add information on how to
contact you by electronic and paper mail.
*/

defined('ABSPATH') || die();

//
// Main action.
//
add_action('plugins_loaded', 'verboten', 1, 0);
function verboten() {
	$status = 0;
	if (empty($_SERVER['REQUEST_URI']) == false) {
		$hostile = implode('|', apply_filters('verboten_request_uris', array(
			'\s',
			'<',
			'>',
			'\^',
			'`',
			'@@',
			'\?\?',
			'\/&&',
			'\\',
			'\/=',
			'\/:\/',
			'\/\/\/',
			'\.\.\.',
			'\/\*(.*)\*\/',
			'\+\+\+',
			'\{0\}',
			'0x00',
			'%00',
			'\(\/\(',
			'(\/|;|=|,)nt\.',
			'@eval',
			'eval\(',
			'union(.*)select',
			'\(null\)',
			'base64_',
			'(\/|%2f)localhost',
			'(\/|%2f)pingserver',
			'wp-config\.php',
			'(\/|\.)(s?ftp-?)?conf(ig)?(uration)?\.',
			'\/wwwroot',
			'\/makefile',
			'crossdomain\.',
			'self\/environ',
			'usr\/bin\/perl',
			'var\/lib\/php',
			'etc\/passwd',
			'\/https:',
			'\/http:',
			'\/ftp:',
			'\/file:',
			'\/php:',
			'\/cgi\/',
			'\.asp',
			'\.bak',
			'\.bash',
			'\.bat',
			'\.cfg',
			'\.cgi',
			'\.cmd',
			'\.conf',
			'\.db',
			'\.dll',
			'\.ds_store',
			'\.exe',
			'\/\.git',
			'\.hta',
			'\.htp',
			'\.inc',
			'\.init?',
			'\.jsp',
			'\.mysql',
			'\.pass',
			'\.pwd',
			'\.sql',
			'\/\.svn',
			'\.exec\(',
			'\)\.html\(',
			'\{x\.html\(',
			'\.php\([0-9]+\)',
			'(benchmark|sleep)(\s|%20)*\(',
			'\/(db|mysql)-?admin',
			'\/document_root',
			'\/error_log',
			'indoxploi',
			'\/sqlpatch',
			'xrumer',
			'www\.(.*)\.cn',
			'%3Cscript',
			'\/vbforum(\/)?',
			'\/vbulletin(\/)?',
			'\{\$itemURL\}',
			'(\/bin\/)(cc|chmod|chsh|cpp|echo|id|kill|mail|nasm|perl|ping|ps|python|tclsh)(\/)?$',
			'((curl_|shell_)?exec|(f|p)open|function|fwrite|leak|p?fsockopen|passthru|phpinfo|posix_(kill|mkfifo|setpgid|setsid|setuid)|proc_(close|get_status|nice|open|terminate)|system)(.*)(\()(.*)(\))',
			'(\/)(^$|0day|configbak|curltest|db|index\.php\/index|(my)?sql|(php|web)?shell|php-?info|temp00|vuln|webconfig)(\.php)'
		)));
		if (empty($hostile) == false) {
			if (strlen($_SERVER['REQUEST_URI']) > 2000 || preg_match(sprintf('#%s#i', $hostile), $_SERVER['REQUEST_URI']) == 1) {
				$status = $status + 1;
			}
		}
	}
	if (empty($_SERVER['QUERY_STRING']) == false) {
		$hostile = implode('|', apply_filters('verboten_query_strings', array(
			'\(0x',
			'0x3c62723e',
			';!--=',
			'\(\)\}',
			':;\};',
			'\.\.\/',
			'\/\*\*\/',
			'127\.0\.0\.1',
			'localhost',
			'loopback',
			'%0a',
			'%0d',
			'%00',
			'%2e%2e',
			'%0d%0a',
			'@copy',
			'concat(.*)(\(|%28)',
			'allow_url_(fopen|include)',
			'(c99|php|web)shell',
			'auto_prepend_file',
			'disable_functions?',
			'gethostbyname',
			'input_file',
			'execute',
			'safe_mode',
			'file_(get|put)_contents',
			'mosconfig',
			'open_basedir',
			'outfile',
			'proc_open',
			'root_path',
			'user_func_array',
			'path=\.',
			'mod=\.',
			'(globals|request)(=|\[)',
			'f(fclose|fgets|fputs|fsbuff)',
			'\$_(env|files|get|post|request|server|session)',
			'(\+|%2b)(concat|delete|get|select|union)(\+|%2b)',
			'(cmd|command)(=|%3d)(chdir|mkdir)',
			'(absolute_|base|root_)(dir|path)(=|%3d)(ftp|https?)',
			'(s)?(ftp|inurl|php)(s)?(:(\/|%2f|%u2215)(\/|%2f|%u2215))',
			'(\/|%2f)(=|%3d|\$&|_mm|cgi(\.|-)|inurl(:|%3a)(\/|%2f)|(mod|path)(=|%3d)(\.|%2e))',
			'(;|<|>|\'|"|\)|%0a|%0d|%22|%27|%3c|%3e|%00)(.*)(\/\*|alter|base64|benchmark|cast|char|concat|convert|create|declare|delete|drop|encode|exec|fopen|function|html|insert|md5|order|request|script|select|set|union|update)'
		)));
		if (empty($hostile) == false) {
			if (preg_match(sprintf('#%s#i', $hostile), $_SERVER['QUERY_STRING']) == 1) {
				$status = $status + 2;
			}
		}
	}
	if (empty($_SERVER['HTTP_USER_AGENT']) == false) {
		$hostile = implode('|', apply_filters('verboten_user_agents', array(
			'&lt;',
			'%0a',
			'%0d',
			'%27',
			'%3c',
			'%3e',
			'%00',
			'0x00',
			'\/bin\/bash',
			'360Spider',
			'acapbot',
			'acoonbot',
			'ahrefs',
			'alexibot',
			'asterias',
			'attackbot',
			'backdorbot',
			'base64_decode',
			'becomebot',
			'binlar',
			'blackwidow',
			'blekkobot',
			'blexbot',
			'blowfish',
			'bullseye',
			'bunnys',
			'butterfly',
			'careerbot',
			'casper',
			'checkpriv',
			'cheesebot',
			'cherrypick',
			'chinaclaw',
			'choppy',
			'clshttp',
			'cmsworld',
			'copernic',
			'copyrightcheck',
			'cosmos',
			'crescent',
			'cy_cho',
			'datacha',
			'demon',
			'diavol',
			'discobot',
			'disconnect',
			'dittospyder',
			'dotbot',
			'dotnetdotcom',
			'dumbot',
			'emailcollector',
			'emailsiphon',
			'emailwolf',
			'eval\(',
			'exabot',
			'extract',
			'eyenetie',
			'feedfinder',
			'flaming',
			'flashget',
			'flicky',
			'foobot',
			'g00g1e',
			'getright',
			'gigabot',
			'go-ahead-got',
			'gozilla',
			'grabnet',
			'grafula',
			'harvest',
			'heritrix',
			'httrack',
			'icarus6j',
			'jetbot',
			'jetcar',
			'jikespider',
			'kmccrew',
			'leechftp',
			'libweb',
			'linkextractor',
			'linkscan',
			'linkwalker',
			'loader',
			'lwp-download',
			'masscan',
			'miner',
			'majestic',
			'md5sum',
			'mechanize',
			'mj12bot',
			'morfeus',
			'moveoverbot',
			'netmechanic',
			'netspider',
			'nicerspro',
			'nikto',
			'ninja',
			'nutch',
			'octopus',
			'pagegrabber',
			'planetwork',
			'postrank',
			'proximic',
			'purebot',
			'pycurl',
			'python',
			'queryn',
			'queryseeker',
			'radian6',
			'radiation',
			'realdownload',
			'remoteview',
			'rogerbot',
			'scooter',
			'seekerspider',
			'semalt',
			'(c99|php|web)shell',
			'shellshock',
			'siclab',
			'sindice',
			'sistrix',
			'sitebot',
			'site(.*)copier',
			'siteexplorer',
			'sitesnagger',
			'skygrid',
			'smartdownload',
			'snoopy',
			'sosospider',
			'spankbot',
			'spbot',
			'sqlmap',
			'stackrambler',
			'stripper',
			'sucker',
			'surftbot',
			'sux0r',
			'suzukacz',
			'suzuran',
			'takeout',
			'teleport',
			'telesoft',
			'true_robots',
			'turingos',
			'turnit',
			'unserialize',
			'vampire',
			'vikspider',
			'voideye',
			'webleacher',
			'webreaper',
			'webstripper',
			'webvac',
			'webviewer',
			'webwhacker',
			'winhttp',
			'wwwoffle',
			'woxbot',
			'xaldon',
			'xxxyy',
			'yamanalab',
			'yioopbot',
			'youda',
			'zeus',
			'zmeu',
			'zune',
			'zyborg'
		)));
		if (empty($hostile) == false) {
			if (preg_match(sprintf('#%s#i', $hostile), $_SERVER['HTTP_USER_AGENT']) == 1) {
				$status = $status + 4;
			}
		}
	}
	if (empty($_SERVER['HTTP_REFERER']) == false) {
		$hostile = implode('|', apply_filters('verboten_referrers', array(
			'ambien',
			'blue\s?pill',
			'ejaculat',
			'erectile',
			'erections',
			'hoodia',
			'huronriver',
			'impotence',
			'levitra',
			'libido',
			'lipitor',
			'phentermin',
			'pro[sz]ac',
			'sandyauer',
			'semalt\.com',
			'todaperfeita',
			'tramadol',
			'ultram',
			'unicauca',
			'valium',
			'viagra',
			'vicodin',
			'xanax',
			'ypxaieo'
		)));
		if (empty($hostile) == false) {
			if (strlen($_SERVER['HTTP_REFERER']) > 2000 || preg_match(sprintf('#%s#i', $hostile), $_SERVER['HTTP_REFERER']) == 1) {
				$status = $status + 8;
			}
		}
	}
	if ($status > 0) {
		header('HTTP/1.1 403 Forbidden');
		header('Status: 403 Forbidden');
		header('Connection: Close');
		if (file_exists(__DIR__ . '/403.php') == true) {
			load_plugin_textdomain('verboten', false, basename(__DIR__) . '/lang/');
			include __DIR__ . '/403.php';
		}
		do_action('verboten_debug', $status);
		exit();
	}	
}

?>
