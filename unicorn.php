<?php

require_once "base_unicorn.php";

class Unicorn extends BaseUnicorn
{
	public function __construct($config) {
		if (!session_id()) {
			session_start();
		}
		parent::__construct($config);
	}

	protected static $kSupportedKeys = 
		array('state','code','access_token','user_id');

	protected function setPersistentData($key, $value) {
		if (!in_array($key, self::$kSupportedKeys)) {
			self::errorLog('Unsupported key passed to setPersistentData.');
			return;
		}

		$session_var_name = $this->constructSessionVariableName($key);
		$_SESSION[$session_var_name] = $value;
	}

	protected function getPersistentData($key, $default = false) {
		if (!in_array($key, self::$kSupportedKeys)) {
			self::errorLog('Unsupported key passed to getPersistentData.');
			return $default;
		}

		$session_var_name = $this->constructSessionVariableName($key);
		return isset($_SESSION[$session_var_name]) ?
		   $_SESSION[$session_var_name]	: $default;
	}

	protected function clearPersistentData($key) {
		if (!in_array($key, self::$kSupportedKeys)) {
			self::errorLog('Unsupported key passed to clearPersistentData.');
			return;
		}

		$session_var_name = $this->constructSessionVariableName($key);
		unset($_SESSION[$session_var_name]);
	}

	protected function clearAllPersistentData() {
		foreach (self::$kSupportedKeys as $key) {
			$this->clearPersistentData($key);
		}
	}

	protected function constructSessionVariableName($key) {
		return implode('_', array('st',
									$this->getAppId(),
									$key));
	}
}
