<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * DNS Library for handling lookups and updates. 
 *
 * PHP Version 5
 *
 * Copyright (c) 2010, Mike Pultz <mike@mikepultz.com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *   * Neither the name of Mike Pultz nor the names of his contributors 
 *     may be used to endorse or promote products derived from this 
 *     software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRIC
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * @category  Networking
 * @package   Net_DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2010 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @version   SVN: $Id$
 * @link      http://pear.php.net/package/Net_DNS2
 * @since     File available since Release 1.0.0
 *
 */

/*
 * register the auto-load function
 *
 */
spl_autoload_register('Net_DNS2::autoload');

/*
 * generate the lookups so they're available everwhere
 *
 */
$GLOBALS['_Net_DNS2_Lookups'] = new Net_DNS2_Lookups();


/**
 * This is the base class for the Net_DNS2_Resolver and Net_DNS2_Updater
 * classes.
 *
 * @category Networking
 * @package  Net_DNS2
 * @author   Mike Pultz <mike@mikepultz.com>
 * @license  http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link     http://pear.php.net/package/Net_DNS2
 * @see      Net_DNS2_Resolver, Net_DNS2_Updater
 *
 */
class Net_DNS2
{
    /*
     * the current version of this library
     */
    const VERSION = "1.0.0";

    /*
     * use TCP only (true/false)
     */
    public $use_tcp = false;

    /*
     * DNS Port to use (53)
     */
    public $dns_port = 53;

    /*
     * the ip/port for use as a local socket
     */
    public $local_host = '';
    public $local_port = 0;

    /*
     * timeout value for socket connections
     */
    public $timeout = 5;

    /*
     * randomize the name servers list
     */
    public $ns_random = false;

    /*
     * default domains
     */
    public $domain = '';

    /*
     * domain search list - not actually used right now
     */
    public $search_list = array();

    /*
     * local sockets
     */
    protected $sockets = array('udp' => array(), 'tcp' => array());

    /*
     * name server list
     */
    protected $nameservers = array();

    /*
     * if the socket extension is loaded
     */
    protected $sockets_enabled = false;

    /*
     * the last erro message returned by the sockets class
     */
    private $_last_socket_error = '';


    /**
     * Constructor - base constructor for the Resolver and Updater
     *
     * @param mixed $options array of options or null for none
     *
     * @access public
     *
     */
    public function __construct(array $options = null)
    {
        //
        // check for the sockets extension
        //
        $this->sockets_enabled = extension_loaded('sockets');

        //
        // load any options that were provided
        //
        if (!empty($options)) {

            foreach ($options as $key => $value) {

                if ($key == 'nameservers') {

                    $this->setServers($value);
                } else {

                    $this->$key = $value;
                }
            }
        }
    }

    /**
     * autoload call-back function; used to auto-load classes
     *
     * @param string $name the name of the class
     *
     * @return void
     * @access public
     *
     */
    static public function autoload($name)
    {
        require str_replace('_', '/', $name) . '.php';
        return;
    }

    /**
     * sets the name servers to be used
     *
     * @param mixed $nameservers either an array of name servers, or a file name to parse, assuming it's
                                 in the resolv.conf format
     *
     * @return boolean
     * @throws Net_DNS2_Exception
     * @access public
     *
     */
    public function setServers($nameservers)
    {
        //
        // if it's an array, then use it directly
        //
        // otherwise, see if it's a path to a resolv.conf file and if so, load it
        //
        if (is_array($nameservers)) {

            $this->nameservers = $nameservers;

        } else {

            //
            // check to see if the file is readable
            //
            if (is_readable($nameservers) === true) {
    
                $data = file_get_contents($nameservers);
                if ($data === false) {
                    throw new Net_DNS2_Exception('failed to read contents of file: ' . $nameservers);
                }

                $lines = explode("\n", $data);

                foreach ($lines as $line) {
                    
                    $line = trim($line);

                    if (strlen($line) == 0) {
                        continue;
                    }

                    list($key, $value) = preg_split('/\s+/', $line, 2);

                    $key     = trim(strtolower($key));
                    $value    = trim(strtolower($value));

                    switch($key) {
                    case 'nameserver':
                        if (preg_match('/^[0-9\.]{7,15}$/', $value)) {

                            $this->nameservers[] = $value;
                        }
                        break;

                    case 'domain':
                        $this->domain = $value;
                        break;

                    case 'search':
                        $this->search_list = preg_split('/\s+/', $value);
                        break;

                    default:
                        ;
                    }
                }

                //
                // if we don't have a domain, but we have a search list, then
                // take the first entry on the search list as the domain
                //
                if ( (strlen($this->domain) == 0) && (count($this->search_list) > 0) ) {

                    $this->domain = $this->search_list[0];
                }

            } else {
                throw new Net_DNS2_Exception('resolver file file provided is not readable: ' . $nameservers);
            }
        }

        //
        // check the name servers
        //
        $this->checkServers();

        return true;
    }

    /**
     * checks the list of name servers to make sure they're set
     *
     * @return boolean
     * @throws Net_DNS2_Exception
     * @access protected
     *
     */
    protected function checkServers()
    {
        if (empty($this->nameservers)) {
            throw new Net_DNS2_Exception('emtpy name servers list; you must provide a list of name servers, or the path to a resolv.conf file.');
        }
    
        return true;
    }

    /**
     * sends a standard Net_DNS2_Packet_Request packet
     *
     * @param Net_DNS2_Packet $request a Net_DNS2_Packet_Request object
     * @param boolean         $use_tcp true/false if the function should use TCP for the request
     *
     * @return mixed returns a Net_DNS2_Packet_Response object, or false on error
     * @throws InvalidArgumentException, Net_DNS2_Exception, Net_DNS2_Socket_Exception
     * @access protected
     *
     */
    protected function sendPacket(Net_DNS2_Packet $request, $use_tcp)
    {
        //
        // get the data from the packet
        //
        $data = $request->get();
        if (strlen($data) < Net_DNS2_Lookups::DNS_HEADER_SIZE) {

            throw new InvalidArgumentException('invalid or empty packet for sending!');
        }

        reset($this->nameservers);
        
        //
        // randomize the name server list if it's asked for
        //
        if ($this->ns_random == true) {

            shuffle($this->nameservers);
        }

        //
        // loop so we can handle server errors
        //
        $response = null;
        $ns = '';
        $tcp_fallback = false;

        while (1) {

            //
            // grab the next DNS server
            //
            if ($tcp_fallback == false) {

                $ns = each($this->nameservers);
                if ($ns === false) {

                    throw new Net_DNS2_Exception('every name server provided has failed: ' . $this->_last_socket_error);
                }

                $ns = $ns[1];
            }

            //
            // if the use TCP flag (force TCP) is set, or the packet is bigger than 512 bytes,
            // use TCP for sending the packet
            //
            if ( ($use_tcp == true) || (strlen($data) > Net_DNS2_Lookups::DNS_MAX_UDP_SIZE) || ($tcp_fallback == true) ) {

                $tcp_fallback = false;

                //
                // create the socket object
                //
                if ( (!isset($this->sockets['tcp'][$ns])) || (!($this->sockets['tcp'][$ns] instanceof Net_DNS2_Socket)) ) {

                    if ($this->sockets_enabled === true) {

                        $this->sockets['tcp'][$ns] = new Net_DNS2_Socket_Sockets(SOCK_STREAM, $ns, $this->dns_port, $this->timeout);
                    } else {

                        $this->sockets['tcp'][$ns] = new Net_DNS2_Socket_Streams(SOCK_STREAM, $ns, $this->dns_port, $this->timeout);
                    }
                }            

                //
                // if a local IP address / port is set, then add it
                //
                if (strlen($this->local_host) > 0) {

                    $this->sockets['tcp'][$ns]->bindAddress($this->local_host, $this->local_port);
                }

                //
                // open it; if it fails, continue in the while loop
                //
                if ($this->sockets['tcp'][$ns]->open() === false) {

                    $this->_last_socket_error = $this->sockets['tcp'][$ns]->last_error;
                    continue;
                }

                //
                // write the data to the socket; if it fails, continue on the while loop
                //
                if ($this->sockets['tcp'][$ns]->write($data) === false) {

                    $this->_last_socket_error = $this->sockets['tcp'][$ns]->last_error;
                    continue;
                }

                //
                // read the content, using select to wait for a response
                //
                $size = 0;

                $result = $this->sockets['tcp'][$ns]->read($size);
                if ( ($result === false) ||  ($size < Net_DNS2_Lookups::DNS_HEADER_SIZE) ) {

                    $this->_last_socket_error = $this->sockets['tcp'][$ns]->last_error;
                    continue;
                }

                //
                // create the packet object
                //
                $response = new Net_DNS2_Packet_Response($result, $size);
                break;

            } else {

                //
                // create the socket object
                //
                if ( (!isset($this->sockets['udp'][$ns])) || (!($this->sockets['udp'][$ns] instanceof Net_DNS2_Socket)) ) {

                    if ($this->sockets_enabled === true) {

                        $this->sockets['udp'][$ns] = new Net_DNS2_Socket_Sockets(SOCK_DGRAM, $ns, $this->dns_port, $this->timeout);
                    } else {

                        $this->sockets['udp'][$ns] = new Net_DNS2_Socket_Streams(SOCK_DGRAM, $ns, $this->dns_port, $this->timeout);
                    }
                }            

                //
                // if a local IP address / port is set, then add it
                //
                if (strlen($this->local_host) > 0) {

                    $this->sockets['udp'][$ns]->bindAddress($this->local_host, $this->local_port);
                }

                //
                // open it
                //
                if ($this->sockets['udp'][$ns]->open() === false) {

                    $this->_last_socket_error = $this->sockets['udp'][$ns]->last_error;
                    continue;
                }

                //
                // write the data to the socket
                //
                if ($this->sockets['udp'][$ns]->write($data) === false) {

                    $this->_last_socket_error = $this->sockets['udp'][$ns]->last_error;
                    continue;
                }

                //
                // read the content, using select to wait for a response
                //
                $size = 0;

                $result = $this->sockets['udp'][$ns]->read($size);
                if (( $result === false) || ($size < Net_DNS2_Lookups::DNS_HEADER_SIZE) ) {

                    $this->_last_socket_error = $this->sockets['udp'][$ns]->last_error;
                    continue;
                }

                //
                // create the packet object
                //
                $response = new Net_DNS2_Packet_Response($result, $size);

                //
                // check the packet header for a trucated bit; if it was truncated, then
                // re-send the request as TCP.
                //
                if ($response->header->tc == 1) {

                    $tcp_fallback = true;
                    continue;
                }

                break;
            }
        }

        if (is_null($response)) {

            return false;
        }

        //
        // make sure header id's match between the request and response
        //
        if ($request->header->id != $response->header->id) {

            throw new Net_DNS2_Exception('invalid response header: the request id does not match the response id');
        }

        //
        // make sure the response is actually a response
        // 
        // 0 = query, 1 = response
        //
        if ($response->header->qr != Net_DNS2_Lookups::QR_RESPONSE) {

            throw new Net_DNS2_Exception('invalid response header: the response provided is not a response packet.');
        }

        //
        // make sure the response code in the header is ok
        //
        if ($response->header->rcode != Net_DNS2_Lookups::RCODE_NOERROR) {

            throw new Net_DNS2_Exception('DNS request failed: ' . Net_DNS2_Lookups::$result_code_messages[$response->header->rcode]);
        }

        return $response;
    }
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * End:
 */
?>