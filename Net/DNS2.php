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
 * @category   Networking
 * @package    Net_DNS2
 * @author     Mike Pultz <mike@mikepultz.com>
 * @copyright  2010 Mike Pultz <mike@mikepultz.com>
 * @license    http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @version    SVN: $Id$
 * @link       http://pear.php.net/package/Net_DNS2
 * @since      File available since Release 1.0.0
 */

class Net_DNS2
{
	//
	// use TCP only (true/false)
	//
	public $use_tcp = false;

	//
	// DNS Port to use (53)
	//
	public $dns_port = 53;

	//
	// the ip/port for use as a local socket
	//
	public $local_host = '';
	public $local_port = 0;

	//
	// timeout value for socket connections
	//
	public $timeout = 5;

	//
	// randomize the name servers list
	//
	public $ns_random = false;

	//
	// local sockets
	//
	protected $_sockets = array('udp' => array(), 'tcp' => array());

	//
	// name server list
	//
	protected $_nameservers = array();

	//
	// if the socket extension is loaded
	//
	protected $_sockets_enabled = false;

	static public function autoload($name)
	{
		require str_replace('_', '/', $name) . '.php';
	}

	//
	// Public functions
	//
	public function __construct(array $options = null)
	{
		//
		// check for the sockets extension
		//
		$this->_sockets_enabled = extension_loaded('sockets');

		//
		// load any options that were provided
		//
		if (!empty($options)) {

			foreach($options as $key => $value) {

				if ($key == 'nameservers') {

					$this->setServers($value);
				} else {

					$this->$key = $value;
				}
			}
		}
	}

	//
	// Private functions
	//
	public function setServers($nameservers)
	{
		//
		// if it's an array, then use it directly
		//
		if (is_array($nameservers)) {

			$this->_nameservers = $nameservers;
		
		//
		// otherwise, see if it's a path to a resolv.conf file and if so, load it
		//
		// TODO: load the file
		//
		} else {
			
		}

		//
		// check the name servers
		//
		$this->_checkServers();

		return true;
	}
	protected function _checkServers()
	{
		if (empty($this->_nameservers)) {

			throw new Net_DNS2_NameServer_Exception('Empty name servers list');
		}
	
		return true;
	}
	protected function _sendPacket(Net_DNS2_Packet $request, $use_tcp)
	{
		//
		// get the data from the packet
		//
		$data = $request->get();
		if (strlen($data) < 12) {

			throw new InvalidArgumentException('invalid or empty packet for sending!');
		}

		reset($this->_nameservers);
		
		//
		// randomize the name server list if it's asked for
		//
		if ($this->ns_random == true) {

			shuffle($this->_nameservers);
		}

		//
		// loop so we can handle server errors
		//
		$response = null;
		$ns = '';
		$tcp_fallback = false;

		while(1)
		{
			//
			// grab the next DNS server
			//
			if ($tcp_fallback == false) {

				$ns = each($this->_nameservers);
				if ($ns === FALSE) {

					throw new Net_DNS2_Socket_Exception('exhausted name server list');
				}
				$ns = $ns[1];
			}

			//
			// if the use TCP flag (force TCP) is set, or the packet is bigger than 512 bytes,
			// use TCP for sending the packet
			//
			if ( ($use_tcp == true) || (strlen($data) > 512) || ($tcp_fallback == true) ) {

				$tcp_fallback = false;

				//
				// create the socket object
				//
				if ( (!isset($this->_sockets['tcp'][$ns])) || (!($this->_sockets['tcp'][$ns] instanceof Net_DNS2_Socket)) ) {

					if ($this->_sockets_enabled === TRUE) {

						$this->_sockets['tcp'][$ns] = new Net_DNS2_Socket_Sockets(SOCK_STREAM, $ns, $this->dns_port, $this->timeout);
					} else {

						$this->_sockets['tcp'][$ns] = new Net_DNS2_Socket_Streams(SOCK_STREAM, $ns, $this->dns_port, $this->timeout);
					}
				}			

				//
				// if a local IP address / port is set, then add it
				//
				if (strlen($this->local_host) > 0) {

					$this->_sockets['tcp'][$ns]->bindAddress($this->local_host, $this->local_port);
				}

				//
				// open it; if it fails, continue in the while loop
				//
				if ($this->_sockets['tcp'][$ns]->open() === false) {

					continue;
				}

				//
				// write the data to the socket; if it fails, continue on the while loop
				//
				if ($this->_sockets['tcp'][$ns]->write($data) === false) {

					continue;
				}

				//
				// read the content, using select to wait for a response
				//
				$size = 0;

				$result = $this->_sockets['tcp'][$ns]->read($size);
				if ( ($result === false) ||  ($size < 12) ) {

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
				if ( (!isset($this->_sockets['udp'][$ns])) || (!($this->_sockets['udp'][$ns] instanceof Net_DNS2_Socket)) ) {

					if ($this->_sockets_enabled === TRUE) {

						$this->_sockets['udp'][$ns] = new Net_DNS2_Socket_Sockets(SOCK_DGRAM, $ns, $this->dns_port, $this->timeout);
					} else {

						$this->_sockets['udp'][$ns] = new Net_DNS2_Socket_Streams(SOCK_DGRAM, $ns, $this->dns_port, $this->timeout);
					}
				}			

				//
				// if a local IP address / port is set, then add it
				//
				if (strlen($this->local_host) > 0) {

					$this->_sockets['udp'][$ns]->bindAddress($this->local_host, $this->local_port);
				}

				//
				// open it
				//
				if ($this->_sockets['udp'][$ns]->open() === false) {

					continue;
				}

				//
				// write the data to the socket
				//
				if ($this->_sockets['udp'][$ns]->write($data) === false) {

					continue;
				}

				//
				// read the content, using select to wait for a response
				//
				$size = 0;

				$result = $this->_sockets['udp'][$ns]->read($size);
				if (( $result === false) || ($size < 12) ) {

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
			// TODO: throw new exception
		}

		//
		// make sure the response is actually a response
		// 
		// 0 = query, 1 = response
		//
		if ($response->header->qr != Net_DNS2_Lookups::QR_QUERY) {
			// TODO: throw new exception
		}

		//
		// make sure the response code in the header is ok
		//
		if ($response->header->rcode != Net_DNS2_Lookups::RCODE_NOERROR) {
			// TODO: throw new exception - include error message
		}

		return $response;
	}
}

//
// register the auto-load functino
//
spl_autoload_register('Net_DNS2::autoload');

//
// generate the lookups so they're available everwhere
//
$GLOBALS['_Net_DNS2_Lookups'] = new Net_DNS2_Lookups();

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * End:
 */
?>
