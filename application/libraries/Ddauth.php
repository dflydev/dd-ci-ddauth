<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/**
 * Ddauth.
 * @package dd_ci_ddauth
 */

/**
 * Ddauth Class.
 * @package dd_ci_ddauth
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
    var $shouldSetCookie = true;

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
     * Config: ddauth_validateCredentialsMethodName
     */
    var $handleAuthSuccessMethodName = null;

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
    var $ddauth_redirects_signin_redirectPath = null;

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
    var $handleAuthSuccessCb = null;

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

        $this->handleAuthSuccessMethodName = $config->item(
            'ddauth_handleAuthSuccessMethodName'
        );

        $this->errorMethodName = $config->item(
            'ddauth_errorMethodName'
        );

        // Redirects
        $this->signinRedirectPath = $config->item(
            'ddauth_redirects_signin_redirectPath'
        );

        // Ticket
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

        if ( ! $this->getSessionData('ddauth.requestedUrl') ) {
            $this->setSessionData('ddauth.requestedUrl', current_url());
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
        if ( $id = $this->validateCredentials($username, $password) ) {
            $this->id = $id;
            $this->_setTicket($this->_generateTicket($this->id));
            $this->isLoggedIn = true;
            $this->reportAuthSuccess(true);
            return $id;
        }
        return null;
    }

    /**
     * Execute authentication
     *
     * Attempts to handle all of the specified automated auth related tasks
     * in one go. Once this method has completed, we should be able to know
     * whether or not the end user is authenticated or not.
     *
     * @return bool Are we authenticated?
     */
    function execute() {

        $this->configure();

        $loggedIn = false;

        $loggedOut = $this->_attemptLogout();

        if ( $this->_attemptLogin() ) {
            $loggedIn = true;
            $loggedOut = false;
        }

        if ( $loggedOut ) {

            // If user is logged out, invalidate our ticket.
            $this->invalidateTicket();

        } elseif ( ! $loggedIn ) {

            // If we are not already listed as having logged in, we should
            // check to see if we are still logged in from before.
            if ( ! $this->_attemptContinuation() ) {
                // If we failed the continuation attempt we should
                // invalidate the ticket.
                $this->invalidateTicket();
            }

        }

        $this->attemptPageView();

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

        $logoutValue = $this->getLogoutParam();

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

        $loginValue = $this->getLoginParam();

        if ( $loginValue ) {

            $username = $this->getLoginUsernameParam();
            $password = $this->getLoginPasswordParam();

            if ( $id = $this->performLogin($username, $password) ) {
                if ( $requestedUrl = $this->getSessionData('ddauth.requestedUrl') ) {
                    $this->unsetSessionData('ddauth.requestedUrl');
                    redirect($requestedUrl);
                }
                return true;
            } else {
                $this->reportError(
                    'attemptLogin.invalid',
                    'Login attempt failure, unknown user or incorrect password'
                );
                $this->invalidateTicket();
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

        $authData = $this->validateAuthAndExtractDataFromInput();

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

            $this->reportError('ticket.keepliave',
                $this->ticketKeepalive . ' / ' .
                $this->ticketExpiration . ' / ' .
                ( $authData['token']['e'] - time() ) .
                ' < ' . ( $this->ticketExpiration - $this->ticketKeepaliveThreshold) );
            if ( $this->ticketKeepalive ) {
                $e = $authData['token']['e'];
                $timeRunning = $this->ticketExpiration - ( $e - time() );
                $this->reportError('ticket.keepliave.timeRunning',
                    $timeRunning);
                if ( $timeRunning > $this->ticketKeepaliveThreshold ) {
                    $this->_setTicket($this->_generateTicket($this->id));
                }

            }
            return true;
        }

        return false;

    }

    /**
     * Attempt a page view
     */
    function attemptPageView() {
        $CI =& get_instance();

    }

    /**
     * Invalidate a ticket
     */
    function invalidateTicket() {
        $this->reportError('ticket.invalidate', 'Invalidating ticket');
        $this->_setCookie(null);
    }

    /**
     * Set a ticket
     */
    function _setTicket($value = null) {
        $this->_setCookie($value);
    }

    /**
     * Generate a ticket
     */
    function _generateTicket($id = null) {
        // TODO: Do we really need this abstraction?
        return $this->generateAuthToken(
            array('u' => $id, 'tt' => 'auth')
        );
    }

    /**
     * Attempt to set a cookie
     * @input mixed $value Value
     */
    function _setCookie($value = null) {
        if ( $this->shouldSetCookie ) {
            $CI =& get_instance();
            $CI->load->helper('cookie');
            set_cookie(array(
                'name' => $this->ticketParamName,
                'value' => $value,
                'expire' => $this->ticketExpiration,
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
    function getLogoutParam() {
        return $this->_getConfigParam(
            'ddauth_params_logout_source',
            'ddauth_params_logout_paramName'
        );
    }

    /**
     * Get the value for the login paramater.
     * @return string
     */
    function getLoginParam() {
        return $this->_getConfigParam(
            'ddauth_params_login_source',
            'ddauth_params_login_paramName'
        );
    }

    /**
     * Get the value for the login username paramater.
     * @return string
     */
    function getLoginUsernameParam() {
        return $this->_getConfigParam(
            'ddauth_params_login_source',
            'ddauth_params_login_usernameParamName'
        );
    }

    /**
     * Get the value for the login password paramater.
     * @return string
     */
    function getLoginPasswordParam() {
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
     */
    function configure() {
        return $this->_controllerMethodCallback(
            $this->configurationMethodName,
            $this->configurationCb
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
    function validateCredentials($username = null, $password = null) {
        return $this->_controllerMethodCallback(
            $this->validateCredentialsMethodName,
            $this->validateCredentialsCb,
            array($username, $password)
        );
    }

    /**
     * Handle authentication success
     * @param bool $isLogin Is this a login success?
     */
    function reportAuthSuccess($isLogin = null) {
        return $this->_controllerMethodCallback(
            $this->handleAuthSuccessMethodName,
            $this->handleAuthSuccessCb,
            array($isLogin)
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
     * Initialize session handling.
     *
     * Session handling can be very specific to an application so we need
     * to be flexible in how we handle sessions. Setting and getting have
     * been abstracted out such that this library only directly refers to
     * setSessionFlashData(), setSessionData(), unsetSessionData() and
     * getSessionData().
     *
     * These methods will call the appropriate implementation based on
     * how the session handling has been setup and initialized here.
     */
    function initSession() {
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
                    $this->setSessionFlashDataCb = array(
                        $this, 'setSessionFlashDataCi'
                    );
                    $this->setSessionDataCb = array(
                        $this, 'setSessionDataCi'
                    );
                    $this->unsetSessionDataCb = array(
                        $this, 'unsetSessionDataCi'
                    );
                    $this->getSessionDataCb = array(
                        $this, 'getSessionDataCi'
                    );
                    break;
                case 'php':
                    // Native PHP sessions are going to be
                    // supported eventually.
                    $this->setSessionFlashDataCb = array(
                        $this, 'setSessionFlashDataPhp'
                    );
                    $this->setSessionDataCb = array(
                        $this, 'setSessionDataPhp'
                    );
                    $this->unsetSessionDataCb = array(
                        $this, 'unsetSessionDataPhp'
                    );
                    $this->getSessionDataCb = array(
                        $this, 'getSessionDataPhp'
                    );
                    break;
                case 'callbacks':
                    // Callbacks for each of these three functions
                    // will be supported eventually.
                    $this->setSessionFlashDataCb = array(
                        $this, 'setSessionFlashDataCallbacks'
                    );
                    $this->setSessionDataCb = array(
                        $this, 'setSessionDataCallbacks'
                    );
                    $this->unsetSessionDataCb = array(
                        $this, 'unsetSessionDataCallbacks'
                    );
                    $this->getSessionDataCb = array(
                        $this, 'getSessionDataCallbacks'
                    );
                    break;
                case 'methods':
                    // Method names to be called on the controller for
                    // each of these three functions will be
                    // supported eventually.
                    $this->setSessionFlashDataCb = array(
                        $this, 'setSessionFlashDataMethods'
                    );
                    $this->setSessionDataCb = array(
                        $this, 'setSessionDataMethods'
                    );
                    $this->unsetSessionDataCb = array(
                        $this, 'unsetSessionDataMethods'
                    );
                    $this->getSessionDataCb = array(
                        $this, 'getSessionDataMethods'
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
    function setSessionFlashData($key, $value = null) {
        if ( ! $this->allowFlash ) {
            return $this->setSessionData($key, $value);
        }
        $this->initSession();
        return call_user_func($this->setSessionFlashDataCb, $key, $value);
    }
    /**
     * Set session data
     *
     * Routes to the appropriate underlying session handler implementation.
     */
    function setSessionData($key, $value = null) {
        $this->initSession();
        return call_user_func($this->setSessionDataCb, $key, $value);
    }

    /**
     * Unset session data
     *
     * Routes to the appropriate underlying session handler implementation.
     */
    function unsetSessionData($key) {
        $this->initSession();
        return call_user_func($this->unsetSessionDataCb, $key);
    }

    /**
     * Get session data
     *
     * Routes to the appropriate underlying session handler implementation.
     */
    function getSessionData($key) {
        $this->initSession();
        return call_user_func($this->getSessionDataCb, $key);
    }

    /**
     * CodeIgniter implementation of setSessionFlashData
     */
    function setSessionFlashDataCi($key, $value = null) {
        $CI =& get_instance();
        return $CI->session->set_flashdata($key, $value);
    }

    /**
     * CodeIgniter implementation of setSessionData
     */
    function setSessionDataCi($key, $value = null) {
        $CI =& get_instance();
        return $CI->session->set_userdata($key, $value);
    }

    /**
     * CodeIgniter implementation of unsetSessionData
     */
    function unsetSessionDataCi($key) {
        $CI =& get_instance();
        return $CI->session->unset_userdata($key);
    }

    /**
     * CodeIgniter implementation of getSessionData
     */
    function getSessionDataCi($key) {
        $CI =& get_instance();
        return $CI->session->userdata($key);
    }

    /**
     * PHP Session implementation of setSessionFlashData
     */
    function setSessionFlashDataPhp($key, $value = null) {
        throw new Exception('Set Session Flash Data for PHP not implemented.');
    }

    /**
     * PHP Session implementation of setSessionData
     */
    function setSessionDataPhp($key, $value = null) {
        throw new Exception('Set Session Data for PHP not implemented.');
    }

    /**
     * PHP Session implementation of unsetSessionData
     */
    function unsetSessionDataPhp($key) {
        throw new Exception('Unset Session Data for PHP not implemented.');
    }

    /**
     * PHP Session implementation of getSessionData
     */
    function getSessionDataPhp($key) {
        throw new Exception('Get Session Data for PHP not implemented.');
    }

    /**
     * Callbacks Session implementation of setSessionFlashData
     */
    function setSessionFlashDataCallbacks($key, $value = null) {
        throw new Exception(
            'Set Session Flash Data for Callbacks not implemented.'
        );
    }

    /**
     * Callbacks Session implementation of setSessionData
     */
    function setSessionDataCallbacks($key, $value = null) {
        throw new Exception('Set Session Data for Callbacks not implemented.');
    }

    /**
     * Callbacks Session implementation of unsetSessionData
     */
    function unsetSessionDataCallbacks($key) {
        throw new Exception(
            'Unset Session Data for Callbacks not implemented.'
        );
    }

    /**
     * Callbacks Session implementation of getSessionData
     */
    function getSessionDataCallbacks($key) {
        throw new Exception('Get Session Data for Callbacks not implemented.');
    }

    /**
     * Methods Session implementation of setSessionFlashData
     */
    function setSessionFlashDataMethods($key, $value = null) {
        throw new Exception(
            'Set Session Flash Data for Methods not implemented.'
        );
    }

    /**
     * Methods Session implementation of setSessionData
     */
    function setSessionDataMethods($key, $value = null) {
        throw new Exception('Set Session Data for Methods not implemented.');
    }

    /**
     * Methods Session implementation of unsetSessionData
     */
    function unsetSessionDataMethods($key) {
        throw new Exception('Unset Session Data for Methods not implemented.');
    }

    /**
     * Methods Session implementation of getSessionData
     */
    function getSessionDataMethods($key) {
        throw new Exception('Get Session Data for Methods not implemented.');
    }

    function validateAuthAndExtractDataFromInput() {

        $CI =& get_instance();
        $CI->load->library('encrypt');

        $input = $CI->input;
        $encrypt = $CI->encrypt;

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

        $parts = array();
        foreach ( explode('&', base64_decode($authString)) as $pair ) {
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

        if ( $parts['h'] == $this->generateDigest($parts['d'], $parts['e']) ) {
            return array(
                'token' => $parts,
                'data' => unserialize($parts['d']),
                'expired' => $expired
            );
        } else {
            return NULL;
        }

    }

    function generateAuthToken($data) {
        $time = time() + $this->ticketExpiration;
        $serializedData = serialize($data);
        $digest = $this->generateDigest($serializedData, $time);
        return base64_encode('e=' . urlencode($time) . '&d=' . urlencode($serializedData) . '&h=' . urlencode($digest));
    }

    function generateDigest($data, $time) {
        $CI =& get_instance();
        $CI->load->library('encrypt');
        return $CI->encrypt->hash(
            $time . $data . $CI->encrypt->encryption_key
        );
    }

}

?>
