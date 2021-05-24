<!DOCTYPE html>
<html lang="<?php echo get_locale(); ?>">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width">
		<meta name="robots" content="noindex, nofollow">
		<title>403 Forbidden</title>
		<style type="text/css">
			body {
				margin: 0;
				padding: 0;
				background: yellow;
			}
			main {
				position: fixed;
				width: 80%;
				top: 50%;
				left: 50%;
				transform: translate(-50%, -50%);
				text-align: center;
				color: black;
			}
			h1 {
				font: normal bold 80px/1.1 monospace;
			}
			p {
				font: normal bold 20px/1.1 monospace;
				word-break: break-word;
			}
		</style>
	</head>
	<body>
		<main>
			<h1><?php echo __('Forbidden', 'verboten'); ?></h1>
			<p><?php echo __('Your request looks suspicious and has been denied by a security policy configured by the website administrator.', 'verboten'); ?></p>
			<p><?php echo sprintf('%s://%s%s', $_SERVER['REQUEST_SCHEME'], $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI']); ?></p>
			<p><?php echo sprintf('%s', $_SERVER['REMOTE_ADDR']); ?><br><?php echo sprintf('%s', date_i18n('YmdHis', time() + (get_option('gmt_offset') * HOUR_IN_SECONDS))); ?><br><?php echo $status; ?></p>
		</main>
	</body>
</html>
