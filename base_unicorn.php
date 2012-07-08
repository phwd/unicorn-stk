<?php

if (!function_exists('curl_init')) {
	throw new Exception('Unicorn needs the CURL PHP extension.');
}
if (!function_exists('json_decode')) {
	throw new Exception('Unicorn needs the JSON PHP extension.');
}

class UnicornApiException extends Exception
{
	protected $result;

	public function __construct($result) {
		$this->result = $result;

		$code = isset($result['error_code']) ? $result['error_code'] : 0;

		if (isset($result['error_description'])) {
			$msg = $result['error_description'];
		} else if (isset($result['error']) && is_array($result['error'])) {
			$msg = $result['error']['message'];
		} else if (isset($result['error_msg'])) {
			$msg = $result['error_msg'];
		} else {
			$msg = 'Unknown Error. Check getResult()';
		}

		parent::__construct($msg, $code);
	}

	public function getResult() {
		return $this->result;
	}

	public function getType() {
		if (isset($this->result['error'])) {
			$error = $this->result['error'];
			if (is_string($error)) {
				return $error;
			} else if (is_array($error)) {
				if (isset($error['type'])) {
					return $error['type'];
				}
			}
		}

		return 'Exception';
	}

	public function __toString() {
		$str = $this->getType() . ': ';
		if ($this->code != 0) {
			$str .= $this->code . ': ';
		}
		return $str . $this->message;
	}
}

abstract class BaseUnicorn
{
	const VERSION = '0.0.1';

	public static $CURL_OPTS = array(
		CURLOPT_CONNECTTIMEOUT => 10,
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_TIMEOUT => 60,
		CURLOPT_USERAGENT => 'unicorn-sdk-0.1',
	);

	protected static $DROP_QUERY_PARAMS = array(
		'code',
		'state',
	);

	public static $DOMAIN_MAP = array(
		'api'	=> 'https://api.stackexchange.com/2.0/',
		'www'	=> 'https://stackexchange.com/',
	);

	protected $appId;
	protected $apiSecret;
	protected $apiKey;

	protected $user;
	protected $state;
	protected $access_token = null;

	public function __construct($config) {
		$this->setAppId($config['appId']);
		$this->setApiSecret($config['secret']);
		$this->setApiKey($config['key']);

		$state = $this->getPersistentData('state');
		if (!empty($state)) {
			$this->state = $this->getPersistentData('state');
		}

		$this->getLogout();
	}

	public function setAppId($appId) {
		$this->appId = $appId;
		return $this;
	}

	public function getAppId() {
		return $this->appId;
	}

	public function setApiSecret($apiSecret) {
		$this->apiSecret = $apiSecret;
		return $this;
	}

	public function getApiSecret() {
		return $this->apiSecret;
	}

	public function setApiKey($apiKey) {
		$this->apiKey = $apiKey;
		return $this;
	}

	public function getApiKey() {
		return $this->apiKey;
	}

	public function setAccessToken($access_token) {
		$this->access_token = $access_token;
		return $this;
	}

	public function getAccessToken() {
		if ($this->accessToken !== null) {
			return $this->accessToken;
		}
		$user_access_token = $this->getUserAccessToken();
		
		if ($user_access_token) {
			$this->setAccessToken($user_access_token);
		} 
		
		return $this->access_token;
	}

	protected function getUserAccessToken() {

		$code = $this->getCode();

		if ($code && $code != $this->getPersistentData('code')) {
		  $access_token = $this->getAccessTokenFromCode($code);
		  if ($access_token) {
			$this->setPersistentData('code', $code);
			$this->setPersistentData('access_token', $access_token);
			return $access_token;
		  }

		  // code was bogus, so everything based on it should be invalidated.
		  $this->clearAllPersistentData();
		  return false;
		}

		// as a fallback, just return whatever is in the persistent
		// store, knowing nothing explicit (signed request, authorization
		// code, etc.) was present to shadow it (or we saw a code in $_REQUEST,
		// but it's the same as what's in the persistent store)

		return $this->getPersistentData('access_token');

	}

	public function getUser() {
		if ($this->user !== null) {
			return $this->$user;
		}

		return $this->user = $this->getUserFromAvailableData();
	}

	protected function getUserFromAvailableData() {
		$user = $this->getPersistentData('user_id', $default = 0);
		$persisted_access_token = $this->getPersistentData('access_token');

		$access_token = $this->getAccessToken();

		if ($access_token && !($user && $persisted_access_token == $access_token)) {
		  $user = $this->getUserFromAccessToken();
		  if ($user) {
			  $this->setPersistentData('user_id', $user);
		  } else {
			  $this->clearAllPersistentData();
		  }
		
		}

		return $user;
	}

	public function getLoginUrl($params=array()) {
		$this->establishCSRFTokenState();
		$currentUrl = $this->getCurrentUrl();

		$scopeParams = isset($params['scope']) ? $params['scope'] : null;
		if ($scopeParams && is_array($scopeParams)) {
			$params['scope'] = implode(',', $scopeParams);
		}

		return $this->getUrl(
			'www',
			'oauth',
			array_merge(array(
							'client_id' => $this->getAppId(),
							'redirect_uri' => $currentUrl,
							'state' => $this->state),
						$params));
	}

	public function getLogoutUrl() {
		return $this->getCurrentUrl() . "?logout=1";
	}

	public function getLogout() {
		if (isset($_REQUEST['logout']) && $_REQUEST['logout'] == 1) {
			$this->destroySession();
		}
	}

	public function api(/* polymorphic */) {
		$args = func_get_args();
		return call_user_func_array(array($this, '_stack'), $args);
	}

	protected function getCode() {
		if (isset($_REQUEST['code'])) {
			if ($this->state !==null &&
				isset($_REQUEST['state']) &&
				$this->state === $_REQUEST['state']) {
					
				$this->state = null;
				$this->clearPersistentData('state');
				
				return $_REQUEST['code'];
			} else {
				self::errorLog('CSRF state token does not match one provided.');
				return false;
			}
	  }

	 return false;
	}

	protected function getUserFromAccessToken() {
		try {
			$user_info = $this->api('/me?site=stackoverflow');
			return $user_info['items'][0]['user_id'];
		} catch (UnicornApiException $e) {
			return 0;
		}
	}

	protected function establishCSRFTokenState() {
		if ($this->state === null) {
			$this->state = md5(uniqid(mt_rand(), true));
			$this->setPersistentData('state', $this->state);
		}
	}

	protected function getAccessTokenFromCode($code, $redirect_uri = null) {
		if (empty($code)) {
			return false;
		}

		if ($redirect_uri === null) {
			$redirect_uri = $this->getCurrentUrl();
		}
		
		try {
			$access_token_response =
				$this->_oauthRequest (
					$this->getUrl('www', '/oauth/access_token'),
					$params = array('client_id' => $this->getAppId(),
									'client_secret' => $this->getApiSecret(),
									'redirect_uri' => $redirect_uri,
									'code' => $code));
		} catch (UnicornApiException $e) {
			return false;
		}

		$response_params = array();
		parse_str($access_token_response, $response_params);


		if (!isset($response_params['access_token'])) {
			return false;
		}
			return $response_params['access_token'];
	}

	protected function _stack($path, $params = array()) {
		$result = json_decode($this->_oauthRequest(
			$this->getUrl('api', $path),
			$params
		), true);
		// results are returned, errors are thrown
		if (is_array($result) && isset($result['error'])) {
			$this->throwAPIException($result);
		}
		
		return $result;
	}

	protected function _oauthRequest($url, $params) {
		if (!isset($params['access_token'])) {
			$params['access_token'] = $this->getAccessToken();
			if (!isset($params['access_token'])) {
				unset($params['access_token']);
			} else {
				$params['key'] = $this->getApiKey();
			}
		}
		// json_encode all params values that are not strings
		foreach ($params as $key => $value) {
			if(!is_string($value)) {
				$params[$key] = json_encode($value);
			}
		}
		return $this->makeRequest($url, $params);
	}

	protected function makeRequest($url, $params, $ch=null) {
		if (!$ch) {
			$ch = curl_init();
		}

		$opts = self::$CURL_OPTS;

		if(preg_match("/access_token/",$url)) {
			$opts[CURLOPT_POSTFIELDS] = $params;
		}
		else {	
			if(preg_match("/[?]/",$url)) {
				if(!empty($params)) {
					$url .= '&' . http_build_query($params, null, '&');
				}
			}
			else {
				$url .= '?' . http_build_query($params, null, '&');
			}
		}

   	 	$opts[CURLOPT_URL] = $url;

    	$opts[CURLOPT_ENCODING] = 'gzip';

		if (isset($opts[CURLOPT_HTTPHEADER])) {
			$existing_headers = $opts[CURLOPT_HTTPHEADER];
			$existing_headers[] = 'Excpect:';
			$opts[CURLOPT_HTTPHEADER] = $existing_headers;
		} else {
			$opts[CURLOPT_HTTPHEADER] = array('Expect:');
		}

		curl_setopt_array($ch, $opts);
		curl_setopt($ch, CURLOPT_ENCODING, 'gzip');
		
		$result = curl_exec($ch);
		
		if ($result === false) {
			$e = new UnicornApiException(array(
				'error_code' => curl_errno($ch),
				'error' => array(
				'message' => curl_error($ch),
				'type' => 'CurlException',
				),
			));
			curl_close($ch);
			throw $e;
		}
		curl_close($ch);
		return $result;
	}

	protected function getUrl($name, $path='', $params=array()) {
		$url = self::$DOMAIN_MAP[$name];
		if ($path) {
			if ($path[0] === '/') {
				$path = substr($path, 1);
			}
			$url .= $path;
		}
		if ($params) {
			$url .= '?' . http_build_query($params, null, '&');
		}

		return $url;

	}

	protected function getCurrentUrl() {
		if (isset($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] == 'on' || $_SERVER['HTTPS'] == 1)
			|| isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https'
		) {
			$protocol = 'https://';
		}
		else {
			$protocol = 'http://';
		}
		$currentUrl = $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

		$parts = parse_url($currentUrl);

		$query = '';
		if (!empty($parts['query'])) {
			//drop known params
			$params = explode('&', $parts['query']);
			$retained_params = array();
			foreach ($params as $param) {
				if ($this->shouldRetainParam($param)) {
					$retained_params[] = $param;
				}
			}
			
			if (!empty($retained_params)) {
				$query = '?'.implode($retained_params, '&');
			}
		}

		// use port if non default
		$port = 
			isset($parts['port']) &&
			(($protocol === 'http://' && $parts['port'] !== 80) ||
			($protocol === 'https://' && $parts['port'] !== 443))
			? ':' . $parts['port'] : '';

		// rebuild
		return $protocol . $parts['host'] . $port . $parts['path'] . $query;
	}

	protected function shouldRetainParam($param) {
		foreach (self::$DROP_QUERY_PARAMS as $drop_query_param)	{
			if (strpos($param, $drop_query_param.'=') === 0) {
				return false;
			}
		}

		return true;
	}

	protected function throwAPIException($result) {
		$e = new UnicornApiException($result);
		switch ($e->getType()) {
			case 'OAuthException':
			case 'invalid_token':
			case 'Exception':
				$message = $e->getMessage();
			if ((strpos($message, 'Error validating access token') !== false) ||
			    (strpos($message, 'Invalid OAuth access token') !== false)) {
			  $this->setAccessToken(null);
			  $this->user = 0;
			  $this->clearAllPersistentData();
			}
		}

		throw $e;
	}

	protected static function errorLog($msg) {
		if (php_sapi_name() != 'cli') {
			error_log($msg);
		}
	//	print 'error_log: '.$msg."\n";

	}

	protected static function base64UrlDecode($input) {
		return base64_decode(strtr($input, '-_', '+/'));
	}

	public function destroySession() {
		$this->setAccessToken(null);
		$this->user = 0;
		$this->clearAllPersistentData();
	}

	abstract protected function setPersistentData($key, $value);

	abstract protected function getPersistentData($key, $default = false);

	abstract protected function clearPersistentData($key);

	abstract protected function clearAllPersistentData();
}
	


