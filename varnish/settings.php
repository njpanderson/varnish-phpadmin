<?php
/* This is a sample configuration file for Varnish PHP Admin
 * Please place this file next to the index.php file wherever it is installed
 * and ensure it is named "settings.php".
 */
return array(
	'password' => '',
	'varnish_data_path' => '/var/varnish/data',
	'apache_hosts_path' => '/path/to/apache/hosts',
	'varnish_socket_ip' => '127.0.0.1',
	'varnish_socket_port' => '80',
	'timezone' => 'Europe/London' // see http://php.net/manual/en/timezones.php
);