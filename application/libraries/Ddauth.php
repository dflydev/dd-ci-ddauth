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
     * Not logged in by default.
     */
    var $isLoggedIn = false;

    function Ddauth() {
        $CFG =& load_class('Config');
        $CFG->load('dd_ci_ddauth');
    }

}

?>
