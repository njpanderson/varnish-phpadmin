<?php
/**
 * Varnish PHP Admin
 * @author: Neil Anderson
 * @license: MIT
 * @version: 0.1.0
 */
session_start();

$params = getParams(array(
	'show-stats' => 'auto',
	'settings' => getSettings(),
	'host' => '',
	'reload' => ''
));

$hosts = hosts::getHostNames(
	$params['settings']['varnish_data_path'] . '/' . $params['settings']['apache_hosts_dir']
);

if (empty($params['host'])) {
	if (count($hosts) > 0) {
		$params['host'] = $hosts[0];
	} else {
		$params['host'] = $_SERVER['HTTP_HOST'];
	}
}

date_default_timezone_set($params['settings']['timezone']);

// send anti-caching headers
header('Cache-control: private, no-cache');
header('Expires: ' . gmdate('D, d M Y H:i:s \G\M\T'));

/**
 * Retrieve settings from the settings.php file
 */
function getSettings() {
	if (file_exists('settings.php') && is_readable('settings.php')) {
		$settings = include 'settings.php';

		$settings = array_merge(array(
			'password' => '',
			'varnish_data_path' => '',
			'apache_hosts_dir' => 'hosts',
			'varnish_stats_dir' => 'stats',
			'varnish_http_ip' => '::1',
			'varnish_http_port' => '80',
			'timezone' => 'Europe/London',
			'varnish_socket_ip' => '::1',
			'varnish_socket_port' => '6082',
			'varnish_socket_secret' => '',
			'varnish_ban_method' => 'http',
			'date_format' => 'j F Y g:i a',
			'page_title' => 'Varnish Status Administration'
		), $settings);

		return $settings;
	} else {
		throw new Exception('The "settings.php" file does not exist. Have you created it?');
	}
}

/**
 * Shortcut method for htmlentities
 */
function entities($str) {
	return htmlentities($str, ENT_QUOTES, 'UTF-8');
}

/**
 * Retrieves the parameters from $_GET
 */
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

/**
 * URL management
 */
class URL {
	static function getBaseUri() {
		return strtok($_SERVER['REQUEST_URI'], '?');
	}

	static function getQueryArgs() {
		if (isset($_GET) && !empty($_GET)) {
			return $_GET;
		} else {
			return array();
		}
	}

	static function get() {
		return $_SERVER['REQUEST_URI'];
	}

	static function getQueryAsInputs($type = 'hidden') {
		$inputs = array();

		foreach (self::getQueryArgs() as $key => $value) {
			$inputs[] = '<input type="' . entities($type) . '" name="' . entities($key) . '" value="' . entities($value) . '"/>';
		}

		return implode($inputs, "\n");
	}

	static function buildQuery(array $params, $encode = true) {
		return http_build_query($params, '', ($encode ? '&amp;' : '&'));
	}

	/**
	 * Replace the current query string with the contents of `$params`.
	 */
	static function replace(array $params = array(), $encode = true) {
		$query = self::buildQuery($params, $encode);

		return self::getBaseUri() . (strlen($query) > 0 ? '?' . $query : '');
	}

	/**
	 * Amend the current query string using the contents of `$params`.
	 * Will not affect existing query elements unless they are defined in the
	 * array. Will remove elements defined with values of `null`.
	 */
	static function amend(array $params = array(), $encode = true) {
		$current = self::getQueryArgs();
		$new = array_merge($current, $params);
		$query = self::buildQuery($new, $encode);

		return self::getBaseUri() . (strlen($query) > 0 ? '?' . $query : '');
	}
}

/**
 * Static class to provide Apache host information
 */
class hosts {
	static $hosts;

	static function getHostNames($hostsPath, $fullPaths = false) {
		if (empty(self::$hosts)) {
			self::$hosts = array();

			if (file_exists($hostsPath) && is_readable($hostsPath)) {
				$iterator = new DirectoryIterator(
					$hostsPath
				);

				foreach ($iterator as $file) {
					if ($file->isDir() && !$file->isDot()) {
						if ($fullPaths) {
							self::$hosts[] = $file->getRealPath();
						} else {
							self::$hosts[] = $file->getBaseName();
						}
					}
				}
			}
		}

		return self::$hosts;
	}
}

/**
 * Sends and receives data to varnish over the administration port
 */
class VarnishSocket {
	private $fp;
	private $params;
	private $auth;

	const NL = "\n";

	const CLIS_SYNTAX = 100;
	const CLIS_UNKNOWN = 101;
	const CLIS_UNIMPL = 102;
	const CLIS_TOOFEW = 104;
	const CLIS_TOOMANY = 105;
	const CLIS_PARAM = 106;
	const CLIS_AUTH = 107;
	const CLIS_OK = 200;
	const CLIS_TRUNCATED = 201;
	const CLIS_CANT = 300;
	const CLIS_COMMS = 400;
	const CLIS_CLOSE = 500;

	function __construct($params) {
		$this->params = $params;
	}

	public function connect() {
		$this->fp = @fsockopen(
			$this->params['settings']['varnish_socket_ip'],
			$this->params['settings']['varnish_socket_port'],
			$errno,
			$errstr,
			5
		);

		// stream_set_timeout($this->fp, 2);

		if (!$this->fp) {
			throw new Exception('Socket error: ' . $errstr . '(' . $errno . ')');
		}

		// get initial authentication response and authenticate
		$response = $this->receive();
		$this->sendAuth($response['message'][0]);
	}

	public function disconnect() {
		fclose($this->fp);
	}

	public function getBanList() {
		$this->checkAuth();
		$response = $this->write('ban.list', self::CLIS_OK);
		$banlist = array();

		for ($a = 1; $a < count($response['message']); $a += 1) {
			preg_match('/([\d\.]+)\s+(\d+)\s([CRO-]+) +(0x[^ ]+)?(.+)?/', $response['message'][$a], $match);

			if (count($match) === 6) {
				$flags = str_split(trim(str_replace('-', '', $match[3])));

				$banlist[] = array(
					'timestamp' => (double) $match[1],
					'gmdate' => gmdate('c', $match[1]),
					'ref' => (int) $match[2],
					'flags' => (count($flags) > 0 && !empty($flags[0]) ? $flags : null),
					'pointer' => (!empty($match[4]) ? $match[4] : null),
					'spec' => trim($match[5])
				);
			}
		}

		return $banlist;
	}

	public function addBan($spec) {
		$response = $this->write('ban ' . $spec);

		switch ($response['code']) {
		case self::CLIS_OK:
			return true;

		default:
			return $response;
		}
	}

	private function sendAuth($challenge) {
		$response = $this->write('auth ' . $this->genAuthCode($challenge));

		if ($response['code'] === self::CLIS_OK) {
			$this->auth = true;
		} else {
			throw new Exception('Authentication failed.');
		}
	}

	private function write($data, $expectedResponseCode = null) {
		if ($this->fp) {
			fwrite($this->fp, $data . self::NL);
			return $this->receive($expectedResponseCode);
		}
	}

	private function receive($expectedResponseCode = null) {
		$response = '';
		$chars_sent = 0;
		$chars_expected = 0;

		while (($line = fgets($this->fp)) !== false) {
			// line starts with numeric code defining the response type and length of response
			if (preg_match('/(\d{3})\s(\d+)/', $line, $code)) {
				// set expected characters (including +1 for terminating newline)
				$chars_expected = (int) $code[2] + 1;
			} else {
				$chars_sent += strlen($line);
			}

			$response .= $line;

			if ($chars_sent >= $chars_expected) {
				break;
			}
		}

		$response = $this->parseResponse($response);

		if (empty($expectedResponseCode) || $response['code'] === $expectedResponseCode) {
			return $response;
		} else {
			throw new Exception('Invalid response from server');
		}
	}

	private function parseResponse($data) {
		$data = explode(self::NL, $data);
		$message = array();

		if (count($data) >= 2) {
			$responseCode = trim($data[0]);
			$responseCode = explode(' ', $responseCode);
			$responseCode = (int) $responseCode[0];

			if (is_numeric($responseCode)) {
				for ($a = 1; $a < count($data); $a += 1) {
					$data[$a] = trim($data[$a]);

					if (!empty($data[$a])) {
						$message[] = $data[$a];
					}
				}
			} else {
				return null;
			}
		}

		return array(
			'code' => $responseCode,
			'message' => $message
		);
	}

	private function genAuthCode($challenge) {
		$string =
			$challenge . self::NL .
			$this->params['settings']['varnish_socket_secret'] . self::NL .
			$challenge . self::NL;

		return hash(
			'sha256',
			$string
		);
	}

	private function checkAuth() {
		if (!$this->fp || !$this->auth) {
			throw new Exception('Connection has not yet taken place. Have you connected with connect()?');
		}
	}
}

/**
 * Sends and receives requests to Varnish over HTTP
 */
class VarnishHTTP {
	function __construct($params) {
		$this->params = $params;
	}

	public function send(
		$host,
		$uri,
		$method = 'GET',
		array $headers = array()
	) {
		$response = '';

		$fp = @fsockopen(
			$this->params['settings']['varnish_http_ip'],
			$this->params['settings']['varnish_http_port'],
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
				'_body' => (isset($response[1]) ? $response[1] : null)
			);
		} else {
			throw new Exception('Socket could not be opened to host. ' . $errstr);
		}
	}
}

/**
 * Static utility class for creating generic data tables
 */
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

/**
 * Handles communincation with Varnish. Will use VarnishSocket or VarnishHTTP
 * classes for certain tasks.
 */
class VarnishCMD {
	private $files;
	private $data;
	private $socket;
	private $http;
	private $banlist;

	protected $params;
	protected $hosts;

	function __construct($params, $hosts) {
		$this->params = $params;
		$this->hosts = $hosts;
	}

	/**
	 * Produces statistics from the most recent snapshot file
	 */
	protected function getStats($withHistory = false) {
		$this->files = $this->getStatFileList();

		if (isset($this->files[0]) && is_readable($this->files[0][1])) {
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
	protected function getHistory($data) {
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

	protected function getTop() {
		return $this->parseTopLines('top.txt');
	}

	protected function getTopMisses() {
		return $this->parseTopLines('top-misses.txt');
	}

	protected function getTopUA() {
		return $this->parseTopLines('top-ua.txt', 'ReqHeader\sUser-Agent\:');
	}

	protected function getBanList($force = false) {
		if (!isset($_SESSION['banlist']) || $force) {
			$_SESSION['banlist'] = $this->getVarnishSocket()->getBanList();
		}

		return $_SESSION['banlist'];
	}

	protected function addPurge($host, $uri) {
		$this->getVarnishHTTP();
		return $this->http->send($host, $uri, 'PURGE');
	}

	protected function addBan($query, $full = false, $host = null) {
		if ($this->params['settings']['varnish_ban_method'] === 'http') {
			// send ban request over http
			if ($full) {
				$headers = array(
					'Ban-Query-Full: ' . $query
				);
			} else {
				$headers = array(
					'Ban-Query: ' . $query
				);
			}

			if (!empty($host)) {
				return $this->getVarnishHTTP()->send($host, '/', 'BAN', $headers);
			} else {
				return 'Invalid hostname';
			}
		}

		if ($this->params['settings']['varnish_ban_method'] === 'admin') {
			// send ban request over admin port
			$query = str_replace("\\", "\\\\", $query);

			if ($full) {
				$response = $this->getVarnishSocket()->addBan($query);
			} else {
				if (!empty($host)) {
					$response = $this->getVarnishSocket()->addBan(
						'req.http.host == "' . $host . '" && req.url ~ "' . $query . '"'
					);
				} else {
					$response = $this->getVarnishSocket()->addBan(
						'req.url ~ \'' . $query . '\''
					);
				}
			}

			if ($response === true) {
				return array(
					'code' => 200,
					'headers' => array('200 Ban added.')
				);
			}

			return array(
				'code' => $response['code'],
				'headers' => $response['message']
			);
		}

		throw new Exception(
			'Invalid ban method "' .
			$this->params['varnish_ban_method'] .
			'". Please choose "http" or "admin".'
		);
	}

	private function getStatFileList() {
		$output = array();
		$statpath = $this->params['settings']['varnish_data_path'] . '/' .
			$this->params['settings']['varnish_stats_dir'];

		if (!file_exists($statpath) || !is_readable($statpath)) {
			return $output;
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

	private function getVarnishSocket() {
		if (!$this->socket) {
			$this->socket = new VarnishSocket($this->params);
			$this->socket->connect();
		}

		return $this->socket;
	}

	private function getVarnishHTTP() {
		if (!$this->http) {
			$this->http = new VarnishHTTP($this->params);
		}

		return $this->http;
	}

	private function parseTopLines($file, $ident = '\w*', $limit = 20) {
		$data = '';

		if (count($this->hosts) > 0) {
			// use host file
			$file = $this->params['settings']['varnish_data_path'] . '/' .
				$this->params['settings']['apache_hosts_dir'] . '/' .
				$this->params['host'] . '/' . $file;
		} else {
			// use server wide file
			$file = $this->params['settings']['varnish_data_path'] . '/' . $file;
		}

		$top = array();

		if (file_exists($file) && is_readable($file)) {
			$data = file_get_contents($file);

			if (!empty($data)) {
				$data = explode("\n", $data);

				for ($a = 0; ($line = $data[$a]) && $a < $limit; $a += 1) {
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
}

class VarnishStats extends VarnishCMD {
	public $uri;
	public $stats;

	function __construct($params, $hosts) {
		parent::__construct($params, $hosts);

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
	function __construct($params, $hosts) {
		parent::__construct($params, $hosts);
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

class VarnishAdmin extends VarnishCMD {
	public $varnish_response;
	public $flashError;

	function __construct($params, $hosts) {
		parent::__construct($params, $hosts);

		if (empty($this->params['settings']['password'])) {
			throw new Exception('Password not defined. Please define a password before continuing!');
		}

		if (isset($_SESSION['varnish_response']) && !empty($_SESSION['varnish_response'])) {
			$this->varnish_response = $_SESSION['varnish_response'];
			unset($_SESSION['varnish_response']);
		}

		if ($_SERVER['REQUEST_METHOD'] === 'POST') {
			$this->handlePost();
		}

		if ($this->params['reload']) {
			// reload cached data sets
			$this->getBanList(true);

			// redirect to version without reload
			$this->redirect(true);
		}
	}

	public function hasSession() {
		return !empty($_SESSION['varnish_user']);
	}

	public function format_varnish_response() {
		$class = '';

		switch ($this->varnish_response['code']) {
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
			$this->varnish_response['headers'][0] .
			'</code></pre>';

		if (isset($this->varnish_response['body'])) {
			$markup .= $this->varnish_response['body'];
		}

		return $markup;
	}

	public function getBanList($force = false) {
		return parent::getBanList($force);
	}

	public function getBanListTable($force = false) {
		$list = $this->getBanList($force);
		$table = '';

		if (is_array($list) && count($list) > 0) {
			$table = '<table class="table table-condensed">';
			$table .= table::thead(array(
				'Date',
				'Ref',
				'Spec'
			));

			foreach ($list as $ban) {
				$table .= table::row(array(
					date($this->params['settings']['date_format'], $ban['timestamp']),
					$ban['ref'],
					$ban['spec']
				));
			}

			$table .= '</table>';
		}

		return $table;
	}

	private function handlePost() {
		if (isset($_POST['ban'])) {
			$this->checkSession();

			$host = $this->params['host'];
			$query = $_POST['query'];

			$response = $this->addBan($query, isset($_POST['full_ban_query']), $host);

			if ($response['code'] === 200 &&
				$this->params['settings']['varnish_ban_method'] === 'admin') {
				// add banlist to response
				$response['body'] =
					'<h3>Ban list</h3>' .
					$this->getBanListTable(true);
			}

			$this->setVarnishResponse(
				$response,
				array(
					'host' => $host,
					'query' => $query
				)
			);
		} elseif (isset($_POST['purge'])) {
			$this->checkSession();

			$host = $this->params['host'];
			$query = $_POST['query'];

			$this->setVarnishResponse(
				$this->addPurge($host, $query),
				array(
					'host' => $host,
					'query' => $query
				)
			);
		} elseif (isset($_POST['login'])) {
			if (!empty($_POST['password']) &&
				$_POST['password'] === $this->params['settings']['password']) {
				$this->setSession('varnish_user', 1);
			} else {
				$this->flashError = 'Invalid password';
			}
		}

		$this->redirect();
	}

	private function setVarnishResponse($value, $data) {
		$this->setSession('varnish_response', array_merge($value, array(
			'data' => $data
		)));
	}

	private function checkSession() {
		if (!$this->hasSession()) {
			header('HTTP/1.1 403 Not Authorized');
			exit;
		}
	}

	private function setSession($key, $value) {
		$_SESSION[$key] = $value;
	}

	private function redirect($clean = false) {
		if ($clean) {
			$url = URL::replace(array(
				'host' => $this->params['host']
			), false);
		} else {
			$url = URL::get();
		}

		header('Location: ' . $url);
		exit;
	}
}

$admin = new VarnishAdmin($params, $hosts);
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

#switchhosts {
	margin-top: 20px;
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
<?php
if (!$admin->hasSession()) {
?>
		<div class="container-fluid head">
			<div class="row">
				<header class="col col-xs-12">
					<h1><?php echo $params['settings']['page_title']?></h1>
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
<?php
} else {
	$stats = new VarnishStats($params, $hosts);
	$top = new VarnishTop($params, $hosts);
?>
		<div class="container-fluid head">
			<div class="row">
				<header class="col col-xs-12">
					<h1 class="pull-left"><?php echo $params['settings']['page_title']?></h1>

					<form action="" id="switchhosts" class="form-inline pull-right">
						<div class="form-group">
							<?php $hostnames = hosts::getHostNames($params['settings']['varnish_data_path'] . '/' . $params['settings']['apache_hosts_dir']); ?>
							<?php if (count($hostnames) > 0): ?>
								<select name="host" id="switchhosts-host" class="form-control" title="Select Host">
									<?php foreach ($hostnames as $host): ?>
										<option<?php if ($host === $params['host']): ?> selected="selected"<?php endif; ?>><?php echo $host; ?></option>
									<?php endforeach; ?>
								</select>
							<?php else: ?>
								<p class="lead"><b><?php echo entities($params['host']); ?></b></p>
							<?php endif; ?>
						</div>
					</form>
				</header>
			</div>

			<div class="row">
				<div class="col col-xs-12">
					<form action="<?php echo URL::get(); ?>" id="purgeban" method="post" class="form-inline">
						<div class="form-group">
							<label for="purgeban-query">Query</label>
							<input type="text" name="query" id="purgeban-query" class="form-control" size="40"/>

							<input type="checkbox" name="full_ban_query" id="purgeban-full-ban-query"/>
							<label for="purgeban-full-ban-query" class="inline">Full ban query</label>
						</div>

						<div class="pull-right">
							<button type="submit" name="purge" class="btn btn-primary"><span class="glyphicon glyphicon-erase"></span>&nbsp;Purge</button>
							<button type="submit" name="ban" class="btn btn-default"><span class="glyphicon glyphicon-asterisk"></span>&nbsp;Ban</button>
						</div>
					</form>
				</div>
			</div>

			<?php if (!empty($admin->varnish_response)): ?>
				<div class="row output">
					<div class="col col-xs-12">
						<div class="well">
							<?php if (!empty($admin->varnish_response['data'])): ?>
							<div class="list-group">
								<?php foreach ($admin->varnish_response['data'] as $key => $value): ?>
									<p class="list-group-item">
										<b><?php echo entities($key) ?></b><span>
										<?php echo entities($value); ?></span>
									</p>
								<?php endforeach; ?>
							</div>
							<?php endif; ?>

							<?php echo $admin->format_varnish_response(); ?>
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
							<h2><span class="glyphicon glyphicon-stats"></span>&nbsp;Global stats</h2>
						</div>

						<div class="col col-xs-12 col-md-6">
							<form action="" id="stats-filter" class="form-inline pull-right">
								<div class="form-group">
									<label>Show</label>
								</div>

								<div class="btn-group" role="group">
									<a href="<?php echo URL::amend(array('show-stats' => null)); ?>" name="show-stats" value="auto" class="btn btn-default<?php echo ($params['show-stats'] == 'auto') ? ' active' : ''; ?>">Auto</a>
									<a href="<?php echo URL::amend(array('show-stats' => 'extended')); ?>" name="show-stats" value="extended" class="btn btn-default<?php echo ($params['show-stats'] == 'extended') ? ' active' : ''; ?>">Extended</a>
									<a href="<?php echo URL::amend(array('show-stats' => 'all')); ?>" name="show-stats" value="all" class="btn btn-default<?php echo ($params['show-stats'] == 'all') ? ' active' : ''; ?>">All</a>
								</div>
							</form>
						</div>
					</div>

					<?php echo $stats->table(); ?>
				</div>

				<div class="col col-xs-12 col-md-6">
					<?php if ($params['settings']['varnish_ban_method'] === 'admin' && $admin->getBanList() > 0): ?>
						<h2>
							<span class="glyphicon glyphicon-asterisk"></span>&nbsp;Ban list
							<a href="<?php echo URL::amend(array('reload' => 1)); ?>" class="btn btn-default pull-right"><span class="glyphicon glyphicon-refresh"></span>&nbsp;Reload</a>
						</h2>
						<?php echo $admin->getBanListTable(); ?>
					<?php endif; ?>

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
<?php
}
?>

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

				$('#switchhosts-host').on('change', function() {
					$(this).closest('form').get(0).submit();
				});

				$(document.body).click(function() {
					$('#purgeban-full-ban-query').popover('hide');
				});
			}());
		</script>
	</body>
</html>