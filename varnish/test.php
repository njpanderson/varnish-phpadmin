<?php
$socket = new VarnishSocket(array(
	'ip' => '139.162.224.23',
	'port' => 6082,
	'secret' => 'f5eacb34-9ffd-425b-ae84-02e8f6ba71de'
));

$socket->connect();

// var_dump($socket->getBanList());
// var_dump($socket->addBan(''));
// var_dump($socket->addBan('req.url ~ \'testing.*\''));
// var_dump($socket->getBanList());

class VarnishSocket {
	private $params;
	private $auth;

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
			$this->params['ip'],
			$this->params['port'],
			$errno,
			$errstr,
			5
		);

		// stream_set_timeout($this->fp, 2);

		if (!$this->fp) {
			throw new Exception($errstr);
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
		$response = $this->write('ban.list', 200);
		$banlist = array();

		for ($a = 1; $a < count($response['message']); $a += 1) {
			preg_match('/([\d\.]+)\s+(\d+)\s([CRO-]+) +(0x[^ ]+)?(.+)?/', $response['message'][$a], $match);

			if (count($match) === 6) {
				$banlist[] = array(
					'timestamp' => (double) $match[1],
					'gmdate' => gmdate('c', $match[1]),
					'ref' => (int) $match[2],
					'flags' => $match[3],
					'pointer' => (!empty($match[4]) ? $match[4] : null),
					'spec' => trim($match[5])
				);
			}
		}

		return $banlist;
	}

	public function addBan($spec) {
		$response = $this->write('ban ' . $spec);

		switch ($response['code'][0]) {
		case 200:
			return true;

		case 104:
			throw new Exception('Unknown ban request');

		default:
			throw new Exception($response['message'][0]);
		}
	}

	private function sendAuth($challenge) {
		$response = $this->write('auth ' . $this->genAuthCode($challenge));

		if ($response['code'][0] === 200 && $response['code'][1] === 248) {
			$this->auth = true;
		} else {
			throw new Exception('Authentication failed.');
		}
	}

	private function write($data, $expectedResponseCode = null) {
		if ($this->fp) {
			fwrite($this->fp, $data . "\r\n");
			return $this->receive($expectedResponseCode);
		}
	}

	private function receive($expectedResponseCode = null) {
		$response = '';
		$code = '';
		$eof = "\n\n";
		$breaks = 1;
		$line = fgets($this->fp);

		while ($line !== false) {
			var_dump($line);
			// line starts with numeric code defining the response type and length of response
			if (preg_match('/(\d{3})\s(\d+)/', $line, $code)) {
				$code[1] = (int) $code[1];
				$code[2] = (int) $code[2];

				if ($code[1] === 107 ||
					($code[1] === 200 && $code[2] === 248)) {
					// increase required number of line break gaps for these response types
					$breaks += 1;
				}

				if ($code[1] === 106 || $code === 104) {
					$eof = "\n";
					$breaks += 1;
				}
			}

			$response .= $line;

			if (substr($response, -strlen($eof), strlen($eof)) === $eof && --$breaks === 0) {
				break;
			}

			$line = fgets($this->fp);
		}

		$response = $this->parseResponse($response);

		if (empty($expectedResponseCode) || $response['code'][0] === $expectedResponseCode) {
			return $response;
		} else {
			throw new Exception('Invalid response from server');
		}
	}

	private function parseResponse($data) {
		$data = explode("\n", $data);
		$message = array();

		if (count($data) >= 2) {
			$responseCode = trim($data[0]);
			$responseCode = explode(' ', $responseCode);

			$responseCode[0] = (int) $responseCode[0];
			$responseCode[1] = (int) $responseCode[1];

			if (count($responseCode) === 2 && is_numeric($responseCode[0])) {
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
		$string = $challenge . chr(0x0A) . $this->params['secret'] . chr(0x0A) . $challenge . "\n";

		return hash(
			'sha256',
			$string
		);
	}

	private function checkAuth() {
		if (!$this->fp || !$this->auth) {
			throw new Exception('Authentication has not yet taken place. Have you connected with connect()?');
		}
	}
}