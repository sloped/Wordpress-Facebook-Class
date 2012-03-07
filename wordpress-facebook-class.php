<?php
/**
 * Copyright 2011 Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

/**
 * Extends the BaseFacebook class with the intent of using
 * PHP sessions to store user ids and access tokens.
 */
class Mspsf_Facebook extends BaseFacebook {

	var $user_id = '';
  
   * @param Array $config the application configuration.
   * @see BaseFacebook::__construct in facebook.php
   */
  public function __construct($config) {
	global $current_user;
	get_currentuserinfo();
	$this->user_id = $current_user->ID;
	parent::__construct($config);
  }

  protected static $kSupportedKeys =
    array('state', 'code', 'access_token', 'user_id');
   
   function extendAccessToken() {
    //function to extend Access Token based on information from https://developers.facebook.com/docs/offline-access-deprecation/
    try {
      // need to circumvent json_decode by calling _oauthRequest
      // directly, since response isn't JSON format.
      $access_token_response =
        $this->_oauthRequest(
          $this->getUrl('graph', '/oauth/access_token'),
          $params = array('client_id' => $this->getAppId(),
                          'client_secret' => $this->getAppSecret(),
                          'grant_type' => 'fb_exchange_token',
                          'fb_exchange_token' => $this->getAccessToken()));
    } catch (FacebookApiException $e) {
      // most likely that user very recently revoked authorization.
      // In any event, we don't have an access token, so say so.
      return false;
    }

    if (empty($access_token_response)) {
      return false;
    }
    $response_params = array();
    parse_str($access_token_response, $response_params);
    if (!isset($response_params['access_token'])) {
      return false;
    }
    return $response_params['access_token'];
  }
  /**
   * Provides the implementations of the inherited abstract functions for persistent data. 
   * Utilizes the wp-option table to store data necessary for the Facebook class to work. 
   */
  protected function setPersistentData($key, $value) {
    if (!in_array($key, self::$kSupportedKeys)) {
		self::errorLog('Unsupported key passed to setPersistentData.');
      return;
    }
    $var_name = $this->constructTransientVariableName($key);
    update_option($var_name, $value);
  }

  protected function getPersistentData($key, $default = false) {
	if (!in_array($key, self::$kSupportedKeys)) {
      self::errorLog('Unsupported key passed to getPersistentData.');
      return $default;
    }
	
    $var_name = $this->constructTransientVariableName($key);

   $return = get_option($var_name);
   if ( false === $return || $return == null) return $default;
  else return $return;
  }

  protected function clearPersistentData($key) {
    if (!in_array($key, self::$kSupportedKeys)) {
      self::errorLog('Unsupported key passed to clearPersistentData.');
      return;
    }

    $var_name = $this->constructTransientVariableName($key);
	delete_option($var_name);
  }

  protected function clearAllPersistentData() {
    foreach (self::$kSupportedKeys as $key) {
      $this->clearPersistentData($key);
    }
  }

  protected function constructTransientVariableName($key) {
	return implode('_', array('facebook',
                              $key));
  }

/**
   * Overrode makeRequest from the base class to implement caching using WP Transients. Cache lifetime is 5 minutes
   * Should be enough to improve site performance. Uses md5 hashes of the url and params to generate unique and standard 
   * length ids. Shouldn't affect access tokens as those call oauthrequest directly. 
   */
 protected function makeRequest($url, $params, $ch=null) {
    if (!$ch) {
      $ch = curl_init();
    }
	$paramstring = implode($params,'_');
	$transient_id = 'fb_request_' .  md5($url . $paramstring);
	$result = get_transient( $transient_id);
	if ( false === $result || $result == null) {
		$opts = self::$CURL_OPTS;
		if ($this->getFileUploadSupport()) {
		  $opts[CURLOPT_POSTFIELDS] = $params;
		} else {
		  $opts[CURLOPT_POSTFIELDS] = http_build_query($params, null, '&');
		}
		$opts[CURLOPT_URL] = $url;

		// disable the 'Expect: 100-continue' behaviour. This causes CURL to wait
		// for 2 seconds if the server does not support this header.
		if (isset($opts[CURLOPT_HTTPHEADER])) {
		  $existing_headers = $opts[CURLOPT_HTTPHEADER];
		  $existing_headers[] = 'Expect:';
		  $opts[CURLOPT_HTTPHEADER] = $existing_headers;
		} else {
		  $opts[CURLOPT_HTTPHEADER] = array('Expect:');
		}

		curl_setopt_array($ch, $opts);
		$result = curl_exec($ch);
		
		if (curl_errno($ch) == 60) { // CURLE_SSL_CACERT
		  self::errorLog('Invalid or no certificate authority found, '.
						 'using bundled information');
		  curl_setopt($ch, CURLOPT_CAINFO,
					  dirname(__FILE__) . '/fb_ca_chain_bundle.crt');
		  $result = curl_exec($ch);
		}

		if ($result === false) {
		  $e = new FacebookApiException(array(
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
    set_transient($transient_id, $result, '300');
  }
	return $result;
  }
  }
?>