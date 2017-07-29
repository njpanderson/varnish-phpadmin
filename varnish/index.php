<?php
/**
 * Varnish PHP Admin
 * @author: Neil Anderson
 * @license: MIT
 */
session_start();

$params = getParams(array(
	'show-stats' => 'auto',
	'settings' => getSettings()
));

date_default_timezone_set($params['settings']['timezone']);

// send anti-caching headers
header('Cache-control: private, no-cache');
header('Expires: ' . gmdate('D, d M Y H:i:s \G\M\T'));

function getSettings() {
	if (file_exists('settings.php') && is_readable('settings.php')) {
		return include 'settings.php';
	} else {
		throw new Exception('The "settings.php" file does not exist. Have you created it?');
	}
}

function entities($str) {
	return htmlentities($str, ENT_QUOTES, 'UTF-8');
}

function getParams($defaults) {
	$params = array();

	foreach ($defaults as $param => $default) {
		if (isset($_GET[$param])) {
			$params[$param] = $_GET[$param];
		} else {
			$params[$param] = $defaults[$param];
		}
	}

	return $params;
}

class hosts {
	static function getHostNames($hosts_path) {
		$files = self::getHostFiles($hosts_path);
		$hosts = array();

		foreach ($files as $file) {
			if (is_readable($file)) {
				$contents = file_get_contents($file);
				preg_match('/ServerName\s+(.*)/', $contents, $servername);
				preg_match_all('/ServerAlias\s+(.*)/', $contents, $serveralias);

				$servername = explode(' ', $servername[1]);
				$hosts = array_merge($hosts, $servername);

				foreach ($serveralias[1] as $aliasline) {
					$aliasline = explode(' ', $aliasline);
					$hosts = array_merge($hosts, $aliasline);
				}
			}
		}

		return $hosts;
	}

	static function getHostFiles($hosts_path) {
		return glob($hosts_path . '/*.conf');
	}
}

class socket {
	public function send(
		$host,
		$uri,
		$method = 'PURGE',
		array $headers = array()
	) {
		$response = '';

		$fp = @fsockopen(
			$this->params['settings']['varnish_socket_ip'],
			$this->params['settings']['varnish_socket_port'],
			$errno,
			$errstr,
			5
		);

		if ($fp) {
			$out = '';
			$body = '';

			$headers = array_merge(array(
				$method . ' ' . $uri . ' HTTP/1.1',
				'Host: ' . $host,
				'Connection: Close'
			), $headers);

			// concatenate socket data
			$out .= implode("\r\n", $headers) . "\r\n\r\n";
			$out .= $body . "\r\n\r\n";

			// write to socket
			fwrite($fp, $out);

			// obtain response then close
			while (!feof($fp)) {
				$response .= fgets($fp, 128);
			}

			fclose($fp);

			// split response into header & body
			$response = explode("\r\n\r\n", $response, 2);
			$response[0] = explode("\r\n", $response[0]);

			// get http code from header
			preg_match('/HTTP\/[\d.]+\s(\d+)/', $response[0][0], $matches);

			if (is_array($matches) && count($matches) === 2) {
				$response_code = (int) $matches[1];
			}

			return array(
				'code' => $response_code,
				'headers' => $response[0],
				'body' => (isset($response[1]) ? $response[1] : null)
			);
		} else {
			throw new Exception('Socket could not be opened to host. ' . $errstr);
		}
	}
}

class table {
	static function thead($cols) {
		$output = '
			<thead>
				<tr>';

		foreach ($cols as $col) {
			$output .= '<th>' . entities($col) . '</th>';
		}

		$output .= '
				</tr>
			</thead>
		';

		return $output;
	}

	static function row($cells, $className = '') {
		$row = '
			<tr' . (!empty($className) ? ' class="' . $className . '"' : '') . '>';

		foreach ($cells as $cell) {
			if (!is_array($cell)) {
				$cell = array(
					'type' => 'td',
					'value' => $cell
				);
			}

			$row .= '<' . $cell['type'] . '>' .
				$cell['value'] .
				'</' . $cell['type'] . '>';
		}

		$row .= '</tr>';

		return $row;
	}
}

class VarnishCMD {
	private $files;
	private $data;

	protected $params;

	function __construct($params) {
		$this->params = $params;
	}

	/**
	 * Produces statistics from the most recent snapshot file
	 */
	public function getStats($withHistory = false) {
		$this->files = $this->getStatFileList();

		if (is_readable($this->files[0][1])) {
			$this->data = json_decode(file_get_contents($this->files[0][1]));

			if ($withHistory) {
				$this->data = $this->getHistory($this->data);
			}

			return $this->data;
		}

		return null;
	}

	/**
	 * Produces historical data given a snapshot
	 */
	public function getHistory($data) {
		if (!$this->files) {
			$this->files = $this->getStatFileList();
		}

		foreach ($this->files as $file) {
			$history = json_decode(file_get_contents($file[1]));

			foreach ($history as $key => $item) {
				if ($key !== 'timestamp') {
					if (!isset($data->{$key}->history)) {
						$data->{$key}->history = array();
					}

					$data->{$key}->history[] = $item->value;
				}
			}
		}

		foreach ($data as &$stat) {
			if (isset($stat->history) && array_sum($stat->history) === 0) {
				$stat->history = null;
			}
		}

		return $data;
	}

	public function getTop() {
		return $this->parseTopLines($this->params['settings']['varnish_data_path'] . '/top.json');
	}

	public function getTopMisses() {
		return $this->parseTopLines($this->params['settings']['varnish_data_path'] . '/top-misses.json');
	}

	public function getTopUA() {
		return $this->parseTopLines($this->params['settings']['varnish_data_path'] . '/top-ua.json', 'ReqHeader\sUser-Agent\:');
	}

	public function parseTopLines($file, $ident = '\w*') {
		$data = '';
		$top = array();

		if (file_exists($file) && is_readable($file)) {
			$data = file_get_contents($file);

			if (!empty($data)) {
				$data = explode("\n", $data);

				foreach ($data as $line) {
					preg_match('/^([\d.]+)\s(' . $ident . ')\s(.*)$/', trim($line), $matches);

					if ($matches !== null && count($matches) === 4) {
						$top[] = array(
							'metric' => $matches[1],
							'data' => $matches[3]
						);
					}
				}
			}
		}

		return $top;
	}

	private function getStatFileList() {
		$output = array();
		$statpath = $this->params['settings']['varnish_data_path'] . '/stat';

		if (!file_exists($statpath) || !is_readable($statpath)) {
			throw new Exception('Varnish stat path "' . $statpath . '" could not be found or could not be read.');
		}

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator(
				$statpath,
				FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS
			)
		);

		foreach ($iterator as $file) {
			if ($file->isFile() && is_numeric($file->getBasename('.json'))) {
				$output[] = array($file->getMTime(), $file->getRealPath());
			}
		}

		usort($output, function($a, $b) {
			// return newest files first
			return $a[0] < $b[0];
		});

		return $output;
	}
}

class VarnishStats extends VarnishCMD {
	public $uri;
	public $stats;

	function __construct($params) {
		parent::__construct($params);

		$this->stats = $this->getStats(true);
		$this->uri = $_SERVER['REQUEST_URI'];
	}

	public function table() {
		$result = '';
		$allowedStats = $this->getAllowedStats($this->params['show-stats']);

		if ($this->stats) {
			$result .= '<table class="table table-striped table-hover table-condensed">';
			$result .= table::thead(array('', 'Current', '10m', '30m', '60m'));
			$result .= '<tbody>';

			foreach ($this->stats as $metric => $data) {
				if (!isset($data->type) || in_array($data->type, $allowedStats)) {
					$result .= $this->row($metric, $data);
				}
			}

			$result .= '</tbody></table>';
		}

		return $result;
	}

	private function getAllowedStats($show) {
		switch ($show) {
		case 'all':
			return array('MAIN', 'SMA', 'MEMPOOL', 'VBE', 'LCK');
			break;

		case 'extended':
			return array('MAIN', 'SMA');
			break;

		default:
			return array('MAIN');
			break;
		}
	}

	/**
	 * Produce a single metric row
	 */
	private function row($metric, $data) {
		$row = '';

		if ($metric !== 'timestamp' && isset($data->value)) {
			if ($data->format !== 'd') {
				$averages = $this->getAverages($metric);
			}

			if ($data->value !== 0 || array_sum($averages) > 0) {
				$cells = array(
					array('type' => 'th', 'value' => $metric . '<span class="desc">' . entities($data->description) . '</span>'),
					$this->format($data->value, $data->format)
				);

				if (isset($averages)) {
					$cells = array_merge($cells, array(
						$this->format($averages[0], $data->format),
						$this->format($averages[1], $data->format),
						$this->format($averages[2], $data->format)
					));
				} else {
					$cells = array_merge($cells, array('', '', ''));
				}

				$row = table::row(
					$cells
				);
			}
		}

		return $row;
	}

	private function format($value, $format) {
		switch ($format) {
		case 'B':
			// bytes
			return $this->formatBytes($value);

		case 'd':
			$dtF = new DateTime('@0');
			$dtT = new DateTime('@' . $value);
			return $dtF->diff($dtT)->format('%aD') .
				'&nbsp;' .
				$dtF->diff($dtT)->format('%H:%I:%s');

		default:
			return $value;
		}
	}

	private function formatBytes($value, $unit = '') {
		if ((!$unit && $value >= 1<<30) || $unit == 'GB')
			return number_format($value/(1<<30),2).'GB';

		if ((!$unit && $value >= 1<<20) || $unit == 'MB')
			return number_format($value/(1<<20),2).'MB';

		if ((!$unit && $value >= 1<<10) || $unit == 'KB')
			return number_format($value/(1<<10),2).'KB';

		return number_format($value) . ' bytes';
	}

	private function getAverages($stat) {
		if (empty($this->stats)) {
			throw new Exception('Stats not yet collected. Have you run getStats?');
		}

		// prefill averages array to 10m, 30m, 60m
		$averages = array(0, 0, 0);

		if (isset($this->stats->{$stat}) &&
			$this->stats->{$stat}->history !== null) {
			// fill 10 minute average
			if (count($this->stats->{$stat}->history) >= 10)
				$averages[0] = $this->median(array_slice($this->stats->{$stat}->history, 0, 10));

			// fill 30 minute average
			if (count($this->stats->{$stat}->history) >= 30)
				$averages[1] = $this->median(array_slice($this->stats->{$stat}->history, 0, 30));

			// fill 60 minute average
			if (count($this->stats->{$stat}->history) >= 60)
				$averages[2] = $this->median(array_slice($this->stats->{$stat}->history, 0, 60));
		}

		return $averages;
	}

	private function median($arr) {
		sort($arr);

		$count = count($arr);
		$middleval = floor(($count-1)/2);

		if ($count % 2) {
			// odd number, middle is the median
			$median = $arr[$middleval];
		} else {
			// even number, calculate avg of 2 medians
			$low = $arr[$middleval];
			$high = $arr[$middleval + 1];
			$median = (($low + $high) / 2);
		}

		return $median;
	}
}

class VarnishTop extends VarnishCMD {
	function __construct($params) {
		parent::__construct($params);
	}

	function table($type) {
		$top = $this->getData($type);
		$result = '';

		$result .= '<table class="table table-striped table-hover table-condensed">';
		$result .= table::thead(array('#', 'Data'));
		$result .= '<tbody>';

		foreach ($top as $data) {
			$result .= table::row(array(
				$data['metric'],
				$data['data']
			));
		}

		$result .= '</tbody></table>';

		return $result;
	}

	private function getData($type) {
		switch ($type) {
		case 'all':
			return $this->getTop();

		case 'misses':
			return $this->getTopMisses();

		case 'ua':
			return $this->getTopUA();
		}
	}
}

class VarnishAdmin {
	public $socket_response;
	public $flashError;

	private $params;

	function __construct($params) {
		$this->params = $params;

		if ($_SERVER['REQUEST_METHOD'] === 'POST') {
			$this->socket_response = $this->handlePost();
		}

		if (empty($this->params['settings']['password'])) {
			throw new Exception('Password not defined. Please define a password before continuing!');
		}
	}

	public function hasSession() {
		return !empty($_SESSION['varnish_user']);
	}

	public function format_socket_response() {
		$class = '';

		switch ($this->socket_response['code']) {
			case 200:
				$class = ' class="label-success"';
				break;

			case 400:
			case 405:
			case 500:
				$class = ' class="label-danger"';
				break;

			default:
				$class = ' class="label-warning"';
		}

		$markup = '<pre' . $class . '><code class="response">' .
			$this->socket_response['headers'][0] .
			'</code></pre>';

		return $markup;
	}

	private function handlePost() {
		$socket_response = 'Invalid action type.';

		if (isset($_POST['ban'])) {
			$host = $_POST['host'];
			$query = $_POST['query'];

			if (isset($_POST['full_ban_query'])) {
				$headers = array(
					'Ban-Query-Full: ' . $query
				);
			} else {
				$headers = array(
					'Ban-Query: ' . $query
				);
			}

			$socket_response = socket::send($host, '/', 'BAN', $headers);
		} elseif (isset($_POST['purge'])) {
			$host = $_POST['host'];
			$query = $_POST['query'];

			$socket_response = socket::send($host, $query);
		} elseif (isset($_POST['login'])) {
			if (!empty($_POST['password']) &&
				$_POST['password'] === $this->params['settings']['password']) {
				$this->setSession();
				$this->redirect($_SERVER['REQUEST_URI']);
			} else {
				$this->flashError = 'Invalid password';
			}
		}

		return $socket_response;
	}

	private function setSession() {
		$_SESSION['varnish_user'] = 1;
	}

	private function redirect($url) {
		header('Location: ' . $url);
		exit;
	}
}

$admin = new VarnishAdmin($params);
$stats = new VarnishStats($params);
$top = new VarnishTop($params);
?>
<!DOCTYPE html>
<html>
	<head>
		<title>Varnish Administration Interface</title>
		<meta name="viewport" content="width=device-width"/>
		<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
		<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous">
		<style>
.row.output {
	margin-top: 1em;
}

.head {
	padding-bottom: 20px;
	border-bottom: 1px solid #ccc;
	background-color: #fafafa;
}

header {
	margin-bottom: 20px;
	border-bottom: 1px solid #808080;
	background-color: #fbe986;
}

#purgeban .form-group {
	margin-right: 10px;
}

#purgeban-query {
	font-family: monospace;
}

pre.label-danger code {
	color: #fee7e5;
}

th span.desc {
	display: block;
	font-size: smaller;
	font-weight: normal;
	color: #544c4d;
}

#stats-filter {
	margin-top: 20px;
}
		</style>
	</head>
	<body>
		<?php if (!$admin->hasSession()): ?>
		<div class="container-fluid head">
			<div class="row">
				<header class="col col-xs-12">
					<h1>Varnish Status Administration</h1>
				</header>
			</div>

			<div class="row">
				<div class="col col-xs-12 col-sm-4 col-sm-offset-4">
					<form action="" id="password" method="post" class="">
						<?php if (!empty($admin->flashError)): ?>
							<p class="text-danger"><b><?php echo $admin->flashError; ?></b></p>
						<?php endif; ?>

						<div class="form-group">
							<label for="password-entry">Password</label>
							<input type="text" name="password" id="password-entry" class="form-control" size="30"/>
						</div>

						<button type="submit" name="login" class="btn btn-primary"><span class="glyphicon glyphicon-log-in"></span>&nbsp;Log In</button>
					</form>
				</div>
			</div>
		</div>
		<?php else: ?>
		<div class="container-fluid head">
			<div class="row">
				<header class="col col-xs-12">
					<h1>Varnish Status Administration</h1>
				</header>
			</div>

			<div class="row">
				<div class="col col-xs-10">
					<form action="" id="purgeban" method="post" class="form-inline">
						<div class="form-group">
							<label for="purgeban-host">Host</label>
							<?php $hostnames = hosts::getHostNames($params['settings']['apache_hosts_path']); ?>
							<?php if (count($hostnames) > 0): ?>
								<select name="host" id="purgeban-host" class="form-control">
									<?php foreach ($hostnames as $host): ?>
										<option<?php if ($host === $_SERVER['HTTP_HOST']): ?> selected="selected"<?php endif; ?>><?php echo $host; ?></option>
									<?php endforeach; ?>
								</select>
							<?php else: ?>
								<input type="text" name="host" id="purgeban-host" class="form-control" size="30" value="<?php echo $_SERVER['HTTP_HOST']; ?>"/>
							<?php endif; ?>
						</div>

						<div class="form-group">
							<label for="purgeban-query">Query</label>
							<input type="text" name="query" id="purgeban-query" class="form-control" size="40"/>

							<input type="checkbox" name="full_ban_query" id="purgeban-full-ban-query"/>
							<label for="purgeban-full-ban-query" class="inline">Full ban query</label>
						</div>

						<button type="submit" name="purge" class="btn btn-primary"><span class="glyphicon glyphicon-refresh"></span>&nbsp;Purge</button>
						<button type="submit" name="ban" class="btn btn-default"><span class="glyphicon glyphicon-ban-circle"></span>&nbsp;Ban</button>
					</form>
				</div>

				<div class="col col-xs-2">
					<p><a class="btn btn-info pull-right" href="<?php echo $stats->uri; ?>">Reload</a></p>
				</div>
			</div>

			<?php if (!empty($admin->socket_response)): ?>
				<div class="row output">
					<div class="col col-xs-12">
						<div class="well">
							<div class="list-group">
								<p class="list-group-item">
									<b>Host:</b> <span><?php echo entities($_POST['host']); ?></span>
								</p>
								<p class="list-group-item">
									<b>Query:</b> <span><?php echo entities($_POST['query']); ?></span>
								</p>
							</div>

							<?php echo $admin->format_socket_response(); ?>
						</div>
					</div>
				</div>
			<?php endif; ?>
		</div>

		<div class="container-fluid stats">
			<div class="row">
				<div class="col col-xs-12 col-md-6">
					<div class="row">
						<div class="col col-xs-12 col-md-6">
							<h2><span class="glyphicon glyphicon-stats"></span>&nbsp;Stats</h2>
						</div>

						<div class="col col-xs-12 col-md-6">
							<form action="" id="stats-filter" class="form-inline pull-right">
								<div class="form-group">
									<label>Show</label>
								</div>

								<div class="btn-group" role="group">
									<button type="submit" name="show-stats" value="auto" class="btn btn-default<?php echo ($params['show-stats'] == 'auto') ? ' active' : ''; ?>">Auto</button>
									<button type="submit" name="show-stats" value="extended" class="btn btn-default<?php echo ($params['show-stats'] == 'extended') ? ' active' : ''; ?>">Extended</button>
									<button type="submit" name="show-stats" value="all" class="btn btn-default<?php echo ($params['show-stats'] == 'all') ? ' active' : ''; ?>">All</button>
								</div>
							</form>
						</div>
					</div>

					<?php echo $stats->table(); ?>
				</div>

				<div class="col col-xs-12 col-md-6">
					<h2><span class="glyphicon glyphicon-sort-by-attributes-alt"></span>&nbsp;Top</h2>

					<h3>All</h3>

					<?php echo $top->table('all'); ?>

					<h3>Misses</h3>

					<?php echo $top->table('misses'); ?>

					<h3>User Agents</h3>

					<?php echo $top->table('ua'); ?>
				</div>
			</div>
		</div>
		<?php endif; ?>

		<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
		<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
		<script>
			(function() {
				var alertedFullBan = false;

				$('#purgeban-full-ban-query').popover({
					content: 'Please be aware that full ban queries can <b class="text-danger">potentially restart Varnish</b>.',
					title: 'Proceed with caution!',
					html: true,
					placement: 'bottom',
					trigger: 'manual'
				});

				$('#purgeban-full-ban-query').on('click', function(event) {
					if (!alertedFullBan && this.checked) {
						event.stopPropagation();
						$(this).popover('show');
						alertedFullBan = true;
					}
				});

				$(document.body).click(function() {
					$('#purgeban-full-ban-query').popover('hide');
				});
			}());
		</script>
	</body>
</html>