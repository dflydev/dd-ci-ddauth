<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/**
 * Ddauth.
 * @package ddauth
 */

/**
 * Ddauth Class.
 * @package ddauth
 */
class Ddauth {

    /**
     * Id of the authenticated user
     */
    var $id = null;

    /**
     * Not logged in by default.
     */
    var $isLoggedIn = false;

    /**
     * Cache of config params.
     */
    var $_configParamCache = array();

    /**
     * Session is not initialized by default.
     */
    var $isSessionInitialized = false;

    /**
     * Should we try to set a cookie?
     */
    var $shouldSendAuthTicketCookie = true;

    /**
     * Name of controller method to call to handle configuration.
     * General configuration.
     * Config: ddauth_configurationMethodName
     */
    var $configurationMethodName = null;

    /**
     * Name of controller method to call to handle credential validation.
     * General configuration.
     * Config: ddauth_validateCredentialsMethodName
     */
    var $validateCredentialsMethodName = null;

    /**
     * Handle authentication success
     * General configuration.
     * Config: ddauth_authSuccessMethodName
     */
    var $authSuccessMethodName = null;

    /**
     * Handle execute complete
     * General configuration.
     * Config: ddauth_executeCompleteMethodName
     */
    var $executeCompleteMethodName = null;

    /**
     * Name of controller method to call to handle errors.
     * General configuration.
     * Config: ddauth_errorMethodName
     */
    var $errorMethodName = null;

    /**
     * Sign in redirect path
     * Redirects configuration.
     * Config: ddauth_redirects_signin_redirectPath
     */
    var $signinRedirectPath = null;

    /**
     * Ticket secret
     * Ticket configuration.
     * Config: ddauth_ticket_secret
     */
    var $ticketSecret = null;

    /**
     * Ticket param name
     * Ticket configuration.
     * Config: ddauth_ticket_paramName
     */
    var $ticketParamName = null;

    /**
     * Ticket expiration time in seconds.
     * Ticket configuration.
     * Config: ddauth_ticket_expiration
     */
    var $ticketExpiration = null;

    /**
     * Ticket keepalive?
     * Ticket configuration.
     * Config: ddauth_ticket_keepalive
     */
    var $ticketKeepalive = null;

    /**
     * Ticket keepalive threshold in seconds
     * Ticket configuration.
     * Config: ddauth_ticket_keepaliveThreshold
     */
    var $ticketKeepaliveThreshold = null;

    /**
     * Ticket cookie domain
     * Ticket configuration.
     * Config: ddauth_ticket_cookie_domain
     */
    var $ticketCookieDomain = null;

    /**
     * Ticket cookie path
     * Ticket configuration.
     * Config: ddauth_ticket_cookie_path
     */
    var $ticketCookiePath = null;

    /**
     * Ticket cookie prefix
     * Ticket configuration.
     * Config: ddauth_ticket_cookie_prefix
     */
    var $ticketCookiePrefix = null;

    /**
     * What type of session handler is used?
     * Session related configuration.
     * Config: ddauth_session_handler
     */
    var $sessionHandler = null;

    /**
     * Use Flash messages?
     * Session related configuration.
     * Config: ddauth_session_allowFlash
     */
    var $allowFlash = null;

    /**
     * Callback to handle configuration.
     */
    var $configurationCb = null;

    /**
     * Callback to handle credential validation.
     */
    var $validateCredentialsCb = null;

    /**
     * Callback to handle authentication success.
     */
    var $authSuccessCb = null;

    /**
     * Callback to handle execute complete.
     */
    var $executeCompleteCb = null;

    /**
     * Callback to handle errors.
     */
    var $errorCb = null;

    /**
     * Constructor
     */
    function Ddauth() {

        $CI =& get_instance();

        $CI->load->helper('url');

        $config = $CI->config;

        $config->load('dd_ci_ddauth');

        $this->configurationMethodName = $config->item(
            'ddauth_configurationMethodName'
        );

        $this->validateCredentialsMethodName = $config->item(
            'ddauth_validateCredentialsMethodName'
        );

        $this->authSuccessMethodName = $config->item(
            'ddauth_authSuccessMethodName'
        );

        $this->executeCompleteMethodName = $config->item(
            'ddauth_executeCompleteMethodName'
        );

        $this->errorMethodName = $config->item(
            'ddauth_errorMethodName'
        );

        // Redirects
        $this->signinRedirectPath = $config->item(
            'ddauth_redirects_signin_redirectPath'
        );

        // Ticket
        $this->ticketSecret = $config->item('ddauth_ticket_secret');
        $this->ticketParamName = $config->item('ddauth_ticket_paramName');
        $this->ticketExpiration = $config->item('ddauth_ticket_expiration');
        $this->ticketKeepalive = $this->_sanitizeBool(
            $config->item('ddauth_ticket_keepalive')
        );
        $this->ticketKeepaliveThreshold = $config->item(
            'ddauth_ticket_keepaliveThreshold'
        );

        $this->ticketCookieDomain = $config->item(
            'ddauth_ticket_cookie_domain'
        );
        $this->ticketCookiePath = $config->item(
            'ddauth_ticket_cookie_path'
        );
        $this->ticketCookiePrefix = $config->item(
            'ddauth_ticket_cookie_prefix'
        );

        // Session
        $this->sessionHandler = $config->item('ddauth_session_handler');
        $this->allowFlash = $config->item('ddauth_session_allowFlash');

    }

    /**
     * Redirect to sign in page
     *
     * Adds the current URL to the session as the requested URL if
     * a requested URL is not already specified and then redirects
     * to the sign in page.
     */
    function redirectToSignin() {

        $CI =& get_instance();
        $CI->load->helper('url');

        if ( ! $this->_getSessionData('ddauth.requestedUrl') ) {
            $this->_setSessionData('ddauth.requestedUrl', current_url());
        }

        redirect($this->signinRedirectPath);

    }

    /**
     * Perform login
     *
     * Performs login for specified username and password. If the
     * credentials validate, the ticket is set and the user identification
     * is returned.
     *
     * @param string $username Username
     * @param string $password Password
     * @return mixed Null or user identification
     */
    function performLogin($username = null, $password = null) {
        if ( $id = $this->_validateCredentials($username, $password) ) {
            return $this->setAuthenticatedId($id, true);
        }
        return null;
    }

    /**
     * Force set the authenticated user ID.
     * @param string $id User ID
     * @param bool $isLogin Is this from a login?
     * @param bool $sendAuthTicketCookie Should an auth ticket cookie be sent?
     * @param int $expires Length of time in seconds that the ticket is valid
     */
    function setAuthenticatedId($id = null, $isLogin = null, $sendAuthTicketCookie = true, $expires = null) {
        $this->id = $id;
        $this->isLoggedIn = true;
        if ( $sendAuthTicketCookie ) {
            $this->_sendAuthTicketCookie(
                $this->generateAuthTicket($id, $expires)
            );
        }
        $this->reportAuthSuccess($isLogin);
        return $this->id;
    }

    /**
     * Invalidate an auth ticket cookie
     */
    function invalidateAuthTicketCookie() {
        $this->_sendAuthTicketCookie(null);
    }

    /**
     * Generate an auth ticket for a user ID
     *
     * This method allows for the generation of a valid authentication ticket
     * for the specified ID.
     *
     * @param mixed $id User ID
     * @param int $expires Length of time in seconds that the ticket is valid
     * @return string
     */
    function generateAuthTicket($id = null, $expires = null) {
        if ( $expires === null ) $expires = $this->ticketExpiration;
        $data = array('u' => $id, 'tt' => 'auth');
        $time = time() + $expires;
        $serializedData = serialize($data);
        $digest = $this->_generateDigest($serializedData, $time);
        return base64_encode('e=' . urlencode($time) . '&d=' . urlencode($serializedData) . '&h=' . urlencode($digest));
    }

    /**
     * Validate an auth ticket
     *
     * Decodes the specified authentication ticket and returns an array
     * containing information about the ticket.
     *
     * @param mixed $rawInput Suspected authentication ticket
     * @return string Authenticated user ID
     */
    function decodeAuthTicket($rawInput = null) {

        if ( $rawInput === null ) return null;

        $parts = array();

        foreach ( explode('&', base64_decode($rawInput)) as $pair ) {
            $keyValuePair = explode('=', $pair);
            if ( count($keyValuePair) == 2 ) {
                list($key, $value) = $keyValuePair;
                $parts[$key] = urldecode($value);
            }
        }

        foreach ( array('e', 'h', 'd') as $k ) {
            if ( ! array_key_exists($k, $parts) ) return NULL;
        }

        $expired = $parts['e'] < time() ? true : false;

        if ( $parts['h'] == $this->_generateDigest($parts['d'], $parts['e']) ) {
            return array(
                'token' => $parts,
                'data' => unserialize($parts['d']),
                'expired' => $expired
            );
        } else {
            return NULL;
        }

    }

    /**
     * Handle authentication success
     * @param bool $isLogin Is this a login success?
     */
    function reportAuthSuccess($isLogin = null) {
        return $this->_controllerMethodCallback(
            $this->authSuccessMethodName,
            $this->authSuccessCb,
            array($isLogin)
        );
    }

    /**
     * Handle execute complete
     */
    function reportExecuteComplete() {
        return $this->_controllerMethodCallback(
            $this->executeCompleteMethodName,
            $this->executeCompleteCb,
            array()
        );
    }

    /**
     * Report errors.
     *
     * Will attempt to execute error callback or call the error method on
     * the controller.
     * @param string $key Short key identifying the error
     * @param string $description Detailed texual description of the error
     */
    function reportError($key, $description) {
        return $this->_controllerMethodCallback(
            $this->errorMethodName,
            $this->errorCb,
            array($key, $description)
        );
    }

    /**
     * Execute authentication
     *
     * Attempts to handle all of the specified automated auth related tasks
     * in one go. Once this method has completed, ddauth should know whether
     * or not the end user has been successfully authenticated or not.
     *
     * Accepts an optional configuration array that will be passed to
     * _configure().
     *
     * @param array $config Additional configuration
     * @return bool Was authentication successful?
     */
    function execute($config = array()) {

        $this->_configure($config);

        $loggedIn = false;

        $loggedOut = $this->_attemptLogout();

        if ( $this->_attemptLogin() ) {
            $loggedIn = true;
            $loggedOut = false;
        }

        if ( $loggedOut ) {

            // If user is logged out, invalidate our ticket.
            $this->invalidateAuthTicketCookie();

        } elseif ( ! $loggedIn ) {

            // If we are not already listed as having logged in, we should
            // check to see if we are still logged in from before.
            if ( ! $this->_attemptContinuation() ) {
                // If we failed the continuation attempt we should
                // invalidate the ticket.
                $this->invalidateAuthTicketCookie();
            }

        }

        $this->reportExecuteComplete();
        return $this->isLoggedIn;

    }

    /**
     * Attempt logging out
     *
     * If `ddauth_params_logout_paramName` exists in the input specified by
     * `ddauth_params_logout_source` the visitor is logged out.
     * @return bool Was log this a log out attempt?
     */
    function _attemptLogout() {

        $CI =& get_instance();
        $config = $CI->config;

        $logoutValue = $this->_getLogoutParam();

        if ( $logoutValue ) {
            // We have asked to log out! We use this state
            // later when we are trying to read auth data.
            return true;
        }

        return false;

    }

    /**
     * Attempt logging in
     *
     * If `ddauth_params_login_paramName` exists in the input specified by
     * `ddauth_params_login_source` the visitor's credentials as specified by
     * `ddauth_params_login_usernameParamName` and
     * `ddauth_params_login_passwordParamName` are tested.
     * @return bool Was log in attempt a success?
     */
    function _attemptLogin() {

        $loginValue = $this->_getLoginParam();

        if ( $loginValue ) {

            $username = $this->_getLoginUsernameParam();
            $password = $this->_getLoginPasswordParam();

            if ( $id = $this->performLogin($username, $password) ) {
                if ( $requestedUrl = $this->_getSessionData('ddauth.requestedUrl') ) {
                    $this->_unsetSessionData('ddauth.requestedUrl');
                    redirect($requestedUrl);
                }
                return true;
            } else {
                $this->reportError(
                    'attemptLogin.invalid',
                    'Login attempt failure, unknown user or incorrect password'
                );
                $this->invalidateAuthTicketCookie();
                $this->redirectToSignin();
            }

        }

        return false;

    }

    /**
     * Attempt continuation of an existing ticket
     *
     * Checks to see if a ticket already exists and validates the ticket and
     * ensures that the ticket has not already expired.
     * @return bool Was continuation attempt a success?
     */
    function _attemptContinuation() {

        $authData = $this->_findAndDecodeAuthTicket();

        // If there was no auth data, this is still a success case since
        // we are going to assume that this is a "continuation" of a
        // non-logged in session.
        if ( $authData === null ) { return true; }

        // If the ticket has expired, this is a failure.
        if ( $authData['expired'] ) { return false; }

        // TODO Do we need to make the ticket type configurable?
        if ( isset($authData['data']['tt']) and $authData['data']['tt'] == 'auth' ) {

            $this->id = $authData['data']['u'];
            $this->isLoggedIn = true;
            $this->reportAuthSuccess(false);

            if ( $this->ticketKeepalive ) {
                $e = $authData['token']['e'];
                $timeRunning = $this->ticketExpiration - ( $e - time() );
                if ( $timeRunning > $this->ticketKeepaliveThreshold ) {
                    $this->_sendAuthTicketCookie(
                        $this->generateAuthTicket($this->id)
                    );
                }

            }

            return true;

        }

        return false;

    }

    /**
     * Send the auth ticket cookie
     * @input mixed $value Value
     * @param int $expires Length of time in seconds that the ticket is valid
     */
    function _sendAuthTicketCookie($value = null, $expires = null) {
        if ( $expires === null ) $expires = $this->ticketExpiration;
        $this->reportError('setCookie', $value);
        if ( $this->shouldSendAuthTicketCookie ) {
            $CI =& get_instance();
            $CI->load->helper('cookie');
            set_cookie(array(
                'name' => $this->ticketParamName,
                'value' => $value,
                'expire' => time() + $expires,
                'domain' => $this->ticketCookieDomain,
                'path' => $this->ticketCookiePath,
                'prefix' => $this->ticketCookiePrefix
            ));
        }
    }

    /**
     * Get the value for the logout paramater.
     * @return string
     */
    function _getLogoutParam() {
        return $this->_getConfigParam(
            'ddauth_params_logout_source',
            'ddauth_params_logout_paramName'
        );
    }

    /**
     * Get the value for the login paramater.
     * @return string
     */
    function _getLoginParam() {
        return $this->_getConfigParam(
            'ddauth_params_login_source',
            'ddauth_params_login_paramName'
        );
    }

    /**
     * Get the value for the login username paramater.
     * @return string
     */
    function _getLoginUsernameParam() {
        return $this->_getConfigParam(
            'ddauth_params_login_source',
            'ddauth_params_login_usernameParamName'
        );
    }

    /**
     * Get the value for the login password paramater.
     * @return string
     */
    function _getLoginPasswordParam() {
        return $this->_getConfigParam(
            'ddauth_params_login_source',
            'ddauth_params_login_passwordParamName'
        );
    }

    /**
     * Get a config param from the request
     *
     * ddauth receives information from the request enviornment and
     * depending on the security requirements, the params may be
     * retrieved by either GET, POST or EITHER.
     *
     * This method ensures that the requested param specified by $configName
     * is only retrieved from the sources described by $sourceName.
     *
     * @param string $sourceName Config name of allowed source
     * @param string $configName Config name of the param
     */
    function _getConfigParam($sourceName, $paramName) {

        if ( isset($this->_configParamCache[$sourceName][$paramName]) ) {
            return $this->_configParamCache[$sourceName][$paramName];
        }

        if ( ! isset($this->_configParamCache[$sourceName]) ) {
            $this->_configParamCache[$sourceName] = array();
        }

        $CI =& get_instance();
        $config = $CI->config;
        $input = $CI->input;

        $source = $this->_sanitizeSource($config->item($sourceName));
        $param = $config->item($paramName);

        $rv = null;

        if ( $source == 'either') {
            $rv = $input->get_post($param);
        }
        elseif ( $source == 'post' ) {
            $rv = $input->post($param);
        }
        elseif ( $source == 'get' ) {
            $rv = $input->get($param);
        }

        $this->_configParamCache[$sourceName][$paramName] = $rv;

        return $rv;

    }

    /**
     * Sanitize a bool value
     * @param mixed $value Input
     * @return bool
     */
    function _sanitizeBool($value = null) {
        if ( $value === true ) return true;
        if ( strtolower($value) == 'true' ) return true;
        if ( $value == 1 ) return true;
        return false;
    }

    /**
     * Sanitize a source value
     * @param mixed $value Input
     * @return string
     */
    function _sanitizeSource($sourceValue) {
        if ( preg_match('/^\s*(either|get|post)\s*$/i', $sourceValue, $matches) ) {
            return strtolower($matches[1]);
        }
        return null;
    }

    /**
     * Call a method on a controller or execute a callback
     *
     * Order of operations is as follows: $cb then controller method
     * @param string $methodName Name of method that should exist on controller
     * @param callback $cb Callback to execute
     * @param array $args Arguments to send to method
     */
    function _controllerMethodCallback($methodName, $cb = null, $args = null) {
        if ( $args === null ) $args = array();
        if ( $cb === null ) {
            $CI =& get_instance();
            if ( method_exists($CI, $methodName) ) {
                $cb = array($CI, $methodName);
            }
        }
        if ( $cb !== null ) { return call_user_func_array($cb, $args); }
    }

    /**
     * Configure.
     *
     * Will attempt to execute configuration callback or call the configuration
     * method on the controller.
     *
     * Optional configuration array can be used to set a select number
     * of options at configuration time. Currently supports:
     *
     * 'shouldSendAuthTicketCookie'
     * 'configurationMethodName'
     * 'validateCredentialsMethodName'
     * 'authSuccessMethodName'
     * 'executeCompleteMethodName'
     * 'errorMethodName'
     * 'configurationCb'
     * 'validateCredentialsCb'
     * 'authSuccessCb'
     * 'executeCompleteCb'
     * 'errorCb'
     *
     * @param array $config Configuration array
     */
    function _configure($config = array()) {
        foreach ( $config as $key => $value ) {
            switch($key) {
                case 'shouldSendAuthTicketCookie':
                case 'configurationMethodName':
                case 'validateCredentialsMethodName':
                case 'authSuccessMethodName':
                case 'executeCompleteMethodName':
                case 'errorMethodName':
                case 'configurationCb':
                case 'validateCredentialsCb':
                case 'authSuccessCb':
                case 'executeCompleteCb':
                case 'errorCb':
                    $this->$key = $value;
                    break;
            }
        }
        return $this->_controllerMethodCallback(
            $this->configurationMethodName,
            $this->configurationCb,
            array($config)
        );
    }

    /**
     * Validate credentials.
     *
     * Will attempt to validate credentials using the credential validation
     * callback or call the credential validation method on the controller.
     * @param string $username Username to validate
     * @param string $password Password to validate
     */
    function _validateCredentials($username = null, $password = null) {
        return $this->_controllerMethodCallback(
            $this->validateCredentialsMethodName,
            $this->validateCredentialsCb,
            array($username, $password)
        );
    }

    /**
     * Initialize session handling.
     *
     * Session handling can be very specific to an application so we need
     * to be flexible in how we handle sessions. Setting and getting have
     * been abstracted out such that this library only directly refers to
     * _setSessionFlashData(), _setSessionData(), _unsetSessionData() and
     * _getSessionData().
     *
     * These methods will call the appropriate implementation based on
     * how the session handling has been setup and initialized here.
     */
    function _initSession() {
        if ( ! $this->isSessionInitialized ) {
            switch($this->sessionHandler) {
                case 'ci':
                    // Native CodeIgnither sessions are what
                    // we prefer so the interface resembles
                    // it a great deal. However, the system
                    // should hopefully be flexible enough
                    // to accommodate many types of session
                    // handling.
                    $CI =& get_instance();
                    $CI->load->library('session');
                    $this->_setSessionFlashDataCb = array(
                        $this, '_setSessionFlashDataCi'
                    );
                    $this->_setSessionDataCb = array(
                        $this, '_setSessionDataCi'
                    );
                    $this->_unsetSessionDataCb = array(
                        $this, '_unsetSessionDataCi'
                    );
                    $this->_getSessionDataCb = array(
                        $this, '_getSessionDataCi'
                    );
                    break;
                case 'php':
                    // Native PHP sessions are going to be
                    // supported eventually.
                    $this->_setSessionFlashDataCb = array(
                        $this, '_setSessionFlashDataPhp'
                    );
                    $this->_setSessionDataCb = array(
                        $this, '_setSessionDataPhp'
                    );
                    $this->_unsetSessionDataCb = array(
                        $this, '_unsetSessionDataPhp'
                    );
                    $this->_getSessionDataCb = array(
                        $this, '_getSessionDataPhp'
                    );
                    break;
                case 'callbacks':
                    // Callbacks for each of these three functions
                    // will be supported eventually.
                    $this->_setSessionFlashDataCb = array(
                        $this, '_setSessionFlashDataCallbacks'
                    );
                    $this->_setSessionDataCb = array(
                        $this, '_setSessionDataCallbacks'
                    );
                    $this->_unsetSessionDataCb = array(
                        $this, '_unsetSessionDataCallbacks'
                    );
                    $this->_getSessionDataCb = array(
                        $this, '_getSessionDataCallbacks'
                    );
                    break;
                case 'methods':
                    // Method names to be called on the controller for
                    // each of these three functions will be
                    // supported eventually.
                    $this->_setSessionFlashDataCb = array(
                        $this, '_setSessionFlashDataMethods'
                    );
                    $this->_setSessionDataCb = array(
                        $this, '_setSessionDataMethods'
                    );
                    $this->_unsetSessionDataCb = array(
                        $this, '_unsetSessionDataMethods'
                    );
                    $this->_getSessionDataCb = array(
                        $this, '_getSessionDataMethods'
                    );
                    break;
                default:
                    $this->reportError(
                        'session.unsupported',
                        'Unsupported session handler specified: "' .
                        $this->sessionHandler .
                        '"'
                    );
                    break;
            }
            $this->isSessionInitialized = true;
        }
    }

    /**
     * Set session flash data
     *
     * Routes to the appropriate underlying session handler implementation.
     */
    function _setSessionFlashData($key, $value = null) {
        if ( ! $this->allowFlash ) {
            return $this->_setSessionData($key, $value);
        }
        $this->_initSession();
        return call_user_func($this->_setSessionFlashDataCb, $key, $value);
    }
    /**
     * Set session data
     *
     * Routes to the appropriate underlying session handler implementation.
     */
    function _setSessionData($key, $value = null) {
        $this->_initSession();
        return call_user_func($this->_setSessionDataCb, $key, $value);
    }

    /**
     * Unset session data
     *
     * Routes to the appropriate underlying session handler implementation.
     */
    function _unsetSessionData($key) {
        $this->_initSession();
        return call_user_func($this->_unsetSessionDataCb, $key);
    }

    /**
     * Get session data
     *
     * Routes to the appropriate underlying session handler implementation.
     */
    function _getSessionData($key) {
        $this->_initSession();
        return call_user_func($this->_getSessionDataCb, $key);
    }

    /**
     * CodeIgniter implementation of _setSessionFlashData
     */
    function _setSessionFlashDataCi($key, $value = null) {
        $CI =& get_instance();
        return $CI->session->set_flashdata($key, $value);
    }

    /**
     * CodeIgniter implementation of _setSessionData
     */
    function _setSessionDataCi($key, $value = null) {
        $CI =& get_instance();
        return $CI->session->set_userdata($key, $value);
    }

    /**
     * CodeIgniter implementation of _unsetSessionData
     */
    function _unsetSessionDataCi($key) {
        $CI =& get_instance();
        return $CI->session->unset_userdata($key);
    }

    /**
     * CodeIgniter implementation of _getSessionData
     */
    function _getSessionDataCi($key) {
        $CI =& get_instance();
        return $CI->session->userdata($key);
    }

    /**
     * PHP Session implementation of _setSessionFlashData
     */
    function _setSessionFlashDataPhp($key, $value = null) {
        throw new Exception('Set Session Flash Data for PHP not implemented.');
    }

    /**
     * PHP Session implementation of _setSessionData
     */
    function _setSessionDataPhp($key, $value = null) {
        throw new Exception('Set Session Data for PHP not implemented.');
    }

    /**
     * PHP Session implementation of _unsetSessionData
     */
    function _unsetSessionDataPhp($key) {
        throw new Exception('Unset Session Data for PHP not implemented.');
    }

    /**
     * PHP Session implementation of _getSessionData
     */
    function _getSessionDataPhp($key) {
        throw new Exception('Get Session Data for PHP not implemented.');
    }

    /**
     * Callbacks Session implementation of _setSessionFlashData
     */
    function _setSessionFlashDataCallbacks($key, $value = null) {
        throw new Exception(
            'Set Session Flash Data for Callbacks not implemented.'
        );
    }

    /**
     * Callbacks Session implementation of _setSessionData
     */
    function _setSessionDataCallbacks($key, $value = null) {
        throw new Exception('Set Session Data for Callbacks not implemented.');
    }

    /**
     * Callbacks Session implementation of _unsetSessionData
     */
    function _unsetSessionDataCallbacks($key) {
        throw new Exception(
            'Unset Session Data for Callbacks not implemented.'
        );
    }

    /**
     * Callbacks Session implementation of _getSessionData
     */
    function _getSessionDataCallbacks($key) {
        throw new Exception('Get Session Data for Callbacks not implemented.');
    }

    /**
     * Methods Session implementation of _setSessionFlashData
     */
    function _setSessionFlashDataMethods($key, $value = null) {
        throw new Exception(
            'Set Session Flash Data for Methods not implemented.'
        );
    }

    /**
     * Methods Session implementation of _setSessionData
     */
    function _setSessionDataMethods($key, $value = null) {
        throw new Exception('Set Session Data for Methods not implemented.');
    }

    /**
     * Methods Session implementation of _unsetSessionData
     */
    function _unsetSessionDataMethods($key) {
        throw new Exception('Unset Session Data for Methods not implemented.');
    }

    /**
     * Methods Session implementation of _getSessionData
     */
    function _getSessionDataMethods($key) {
        throw new Exception('Get Session Data for Methods not implemented.');
    }

    /**
     * Find and decode auth ticket from request
     */
    function _findAndDecodeAuthTicket() {

        $CI =& get_instance();

        $input = $CI->input;

        $key = $this->ticketParamName;

        // This little IF block is designed to find the first
        // place that the specified key exists and then break.
        // If we get through all three input sources and still
        // do not have any auth string, we return NULL so that
        // the calller knows that we were not able to validate
        // auth.
        if ( ! (
            ( ( $authString = $input->get($key) ) != "" ) or
            ( ( $authString = $input->post($key) ) != "" ) or
            ( ( $authString = $input->cookie($key) ) != "" )
        ) ) {
            return NULL;
        }

        $authTicket = $this->decodeAuthTicket($authString);
        if ( $authTicket === null ) {
            // We found an auth string but it is invalid! We should
            // make sure that nobody tries this funny business
            // again!
            $this->invalidateAuthTicketCookie();
        }
        return $authTicket;

    }

    /**
     * Generate a digest for the specified data and expiration time
     * @param string $data Data
     * @param int $time Expiration time
     * @return string
     */
    function _generateDigest($data, $time) {
        return sha1( $time . $data . $this->ticketSecret );
    }

}

?>
