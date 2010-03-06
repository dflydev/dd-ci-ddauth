<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');

/**
 * Configuration method name
 *
 * This method will be called on the controller if the controller
 * implements this method.
 *
 * This method can be used to do controller-specific configuration
 * of ddauth prior to ddauth doing its work.
 */
$config['ddauth_configurationMethodName'] = 'configureDdAuth'


/**
 * LOG OUT
 */

/**
 * Log out param source
 *
 * post - Param must come by way of POST method
 * get - Param must come by way of GET method
 * either - Param can come from either GET or POST method
 */
$config['ddauth_params_logout_source'] = 'either';

/**
 * Log out param name
 *
 * If this param exists, trigger log out functionality.
 */
$config['ddauth_params_logout_paramName'] = 'ddauth_logout';


/**
 * LOG IN
 */

/**
 * Log in params source
 *
 * post - Param must come by way of POST method
 * get - Param must come by way of GET method
 * either - Param can come from either GET or POST method
 */
$config['ddauth_params_login_source'] = 'post';

/**
 * Log in param name
 *
 * If this param exists, trigger log in functionality.
 */
$config['ddauth_params_login_paramName'] = 'ddauth_login';

/**
 * Log in username param name
 */
$config['ddauth_params_login_usernameParamName'] = 'ddauth_username';

/**
 * Log in password param name
 */
$config['ddauth_params_login_passwordParamName'] = 'ddauth_password';


/**
 * REDIRECTS
 */

/**
 * Sign in redirect path
 *
 * Should a sign in be required, to where should the client be redirected?
 */
$config['ddauth_redirects_signin_redirectPath'] = 'signin'


/**
 * TICKET
 */

/**
 * Ticket param name
 *
 * The cookie or request param name that contains the ticket.
 */
$config['ddauth_ticket_paramName'] = 'ddauth';

/**
 * Ticket expiration time in seconds.
 */
$config['ddauth_ticket_expiration'] = 18000; # five hours (60*60*5)

/**
 * Ticket keepalive?
 *
 * If true, the ticket will be replaced with a fresh ticket on every
 * request keeping the ticket alive as long as the user continues to
 * visit the site before the most recent ticket expires.
 */
$config['ddauth_ticket_keepalive'] = true;

/**
 * Ticket cookie domain
 *
 * If cookie domain cannot be determined automatically, set it here.
 */
$config['ddauth_ticket_cookie_domain'] = null;

/**
 * Ticket cookie path
 *
 * If cookie path cannot be dtermined automatically, set it here.
 */
$config['ddauth_ticket_cookie_path']


// Include site-specific ddauth configuration if it exists.
$siteConfig = APPPATH.'config/dd_ci_ddauth_site'.EXT;
if ( file_exists($siteConfig) ) include($siteConfig);

?>