<!DOCTYPE html>
<html lang="<?php echo get_locale(); ?>">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width">
		<meta name="robots" content="noindex, nofollow">
		<title>403 Forbidden</title>
		<style type="text/css">
			html, body, div {
				margin: 0;
				padding: 0;
			}
			body {
				background: yellow;
			}
			div {
				position: fixed;
				width: 80%;
				top: 50%;
				left: 50%;
				transform: translate(-50%, -50%);
				text-align: center;
				color: black;
			}
			h1, p {
				margin: 24px 0;
				padding: 0;
			}
			h1 {
				font: normal bold 72px/1.1 monospace;
			}
			p {
				font: normal bold 24px/1.1 monospace;
			}
			code {
				font: italic bold 24px/1.1 monospace;
			}
		</style>
	</head>
	<body>
		<div>
			<h1><?php echo __('Forbidden', 'verboten'); ?></h1>
			<p><?php echo __('Your request looks suspicious and has been denied by a security policy configured by the website administrator.', 'verboten'); ?></p>
			<p><code><?php echo sprintf('%s://%s%s', $_SERVER['REQUEST_SCHEME'], $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI']); ?></code></p>
		</div>
	</body>
</html>
