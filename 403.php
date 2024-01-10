<!DOCTYPE html>
<html lang="<?php echo $atts['locale']; ?>">
	<head>
		<meta charset="</php echo $atts['charset']; ?>">
		<meta name="viewport" content="width=device-width">
		<meta name="robots" content="noindex, nofollow">
		<title><?php echo $atts['title']; ?></title>
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
				font: normal bold 60px/1.1 monospace;
			}
			p {
				font: normal bold 20px/1.1 monospace;
				word-break: break-word;
			}
		</style>
	</head>
	<body>
		<main>
			<h1><?php echo $atts['heading']; ?></h1>
			<p><?php echo $atts['message']; ?></p>
			<p><?php echo $atts['uri']; ?></p>
			<p><?php echo $atts['status']; ?><br><?php echo $atts['time']; ?><br><?php echo $atts['ip']; ?></p>
		</main>
	</body>
</html>
