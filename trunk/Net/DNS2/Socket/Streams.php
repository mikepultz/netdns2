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

class Net_DNS2_Socket_Streams extends Net_DNS2_Socket
{
	private $_context;

	public function open()
	{
		//
		// create a list of options for the context 
		//
		$opts = array('socket' => array());
		
		//
		// bind to a local IP/port if it's set
		//
		// bindto was only added in v5.1.0
		//
		if ( (strlen($this->_local_host) > 0) && (version_compare(PHP_VERSION, '5.1.0', '>=') === TRUE) ) {

			$opts['socket']['bindto'] = $this->_local_host;
			if ($this->_local_port > 0) {

				$opts['socket']['bindto'] .= ':' . $this->_local_port;
			}
		}

		//
		// create the context
		//
		$this->_context = @stream_context_create($opts);

		//
		// create socket
		//
		$errno;
		$errstr;

		switch($this->_type)
		{
			case SOCK_STREAM:
				$this->_sock = @stream_socket_client('tcp://' . $this->_host . ':' . $this->_port, 
					$errno, $errstr, $this->_timeout, STREAM_CLIENT_CONNECT, $this->_context);
			break;
			case SOCK_DGRAM:
				$this->_sock = @stream_socket_client('udp://' . $this->_host . ':' . $this->_port, 
					$errno, $errstr, $this->_timeout, STREAM_CLIENT_CONNECT, $this->_context);
			break;
			default:

				$this->last_error = 'Invalid socket type: ' . $this->_type;
				return false;
		}

		if ($this->_sock === FALSE) {

			$this->last_error = $errstr;
			return false;
		}

		//
		// set it to non-blocking and set the timeout
		//
		@stream_set_blocking($this->_sock, 0);
		@stream_set_timeout($this->_sock, $this->_timeout);

		return true;
	}
	public function close()
	{
		if (is_resource($this->_sock) === TRUE) {

			@fclose($this->_sock);
		}
		return true;
	}
	public function write($data)
	{
		$read = null;
		$write = array($this->_sock);
		$except = null;

		//
		// select on write
		//
		switch(@stream_select($read, $write, $except, $this->_timeout))
		{
			case false:
				$this->last_error = 'failed on stream_select()';
				return false;
			break;
			case 0:
				return false;
			break;
			default:
				;
		}

		//
		// if it's a TCP socket, then we need to packet and send the length of the
		// data as the first 16bit of data.
		//		
		if ($this->_type == SOCK_STREAM) {

			$length = pack('n', strlen($data));

			if (@fwrite($this->_sock, $length) === FALSE) {

				$this->last_error = 'failed to fwrite() 16bit length';
				return false;
			}
		}

		//
		// write the data to the socket
		//
		$size = @fwrite($this->_sock, $data);
		if ( ($size === FALSE) || ($size != strlen($data)) ) {
		
			$this->last_error = 'failed to fwrite() packet';
			return false;
		}

		return true;
	}
	public function read(&$size)
	{
		$read = array($this->_sock);
		$write = null;
		$except = null;

		//
		// select on read
		//
		switch(stream_select($read, $write, $except, $this->_timeout))
		{
			case false:
				$this->last_error = 'error on stream_select()';
				return false;
			break;
			case 0:
				return false;
			break;
			default:
				;
		}

		$data = '';
		$length = 512;

        //
        // if it's a TCP socket, then the first two bytes is the length of the DNS
        // packet- we need to read that off first, then use that value for the    
        // packet read.
        //
		if ($this->_type == SOCK_STREAM) {
	
			if (($data = fread($this->_sock, 2)) === FALSE) {
				
				$this->last_error = 'failed on fread() for data length';
				return false;
			}
		
			$x = unpack('nlength', $data);
			$data = '';

			$length = $x['length'];
			if ($length < 12) {
				return false;
			}
		}

		//
		// read the data from the socket
		//
		if (($data = fread($this->_sock, $length)) === FALSE) {
			
			$this->last_error = 'failed on fread() for data';
			return false;
		}
		
		$size = strlen($data);

		return $data;
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
