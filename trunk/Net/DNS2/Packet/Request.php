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
 * @category	Networking
 * @package		Net_DNS2
 * @author		Mike Pultz <mike@mikepultz.com>
 * @copyright	2010 Mike Pultz <mike@mikepultz.com>
 * @license		http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @version		SVN: $Id$
 * @link		http://pear.php.net/package/Net_DNS2
 * @since		File available since Release 1.0.0
 *
 */


/**
 * This class handles building new DNS request packets; packets used for DNS
 * queries and updates.
 * 
 * @package     Net_DNS2
 * @author      Mike Pultz <mike@mikepultz.com>
 * @see         Net_DNS2_Packet
 *   
 */
class Net_DNS2_Packet_Request extends Net_DNS2_Packet
{
    /**
     * Constructor - builds a new Net_DNS2_Packet_Request object
     *
     * @param   string	$name	the domain name for the packet
	 * @param	string	$type	the DNS RR type for the packet
	 * @param	string	$class	the DNS class for the packet
     * @throws  InvalidArgumentException
	 * @access	public
     *
     */
	public function __construct($name, $type = null, $class = null)
	{
		$this->set($name, $type, $class);
	}

    /**
     * builds a new Net_DNS2_Packet_Request object
     *
     * @param   string	$name	the domain name for the packet
	 * @param	string	$type	the DNS RR type for the packet
	 * @param	string	$class	the DNS class for the packet
	 * @return	boolean
     * @throws  InvalidArgumentException
	 * @access	public
     *
     */
	public function set($name, $type = 'A', $class = 'IN')
	{
		//
		// generate a new header
		//
		$this->header = new Net_DNS2_Header;

		//
		// add a new question
		//
		$q = new Net_DNS2_Question();

		$name	= trim($name, " \t\n\r\0\x0B.");
		$type	= strtoupper(trim($type));
		$class	= strtoupper(trim($class));

		//
		// check that the input string has some data in it
		//
		if (empty($name)) {

			throw new InvalidArgumentException('empty query string provided');
		}

		//
		// if the type is "*", rename it to "ANY"- both are acceptable.
		//
		if ($type == '*') {

			$type = 'ANY';
		}

		//
		// check that the type and class are valid
		//    
		if ( (!isset(Net_DNS2_Lookups::$rr_types_by_name[$type])) || (!isset(Net_DNS2_Lookups::$classes_by_name[$class])) ) {

			throw new InvalidArgumentException('invalid type (' . $type . ') or class (' . $class . ') specified.');
		}

		//
		// if it's a PTR request for an IP address, then make sure we tack on the arpa domain
		//
		// TODO: handle IPv6
		//
		if ( ($type == 'PTR') && (preg_match('/^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/', $name, $a)) ) {
			$name = $a[4] . '.' . $a[3] . '.' . $a[2] . '.' . $a[1] . '.in-addr.arpa';
		}

		//
		// store the data
		//
		$q->qname    = $name;
		$q->qtype    = $type;
		$q->qclass   = $class;		

		$this->question[]   = $q;

		//
		// the answer, authority and additional are empty; they can be modified
		// after the request is created for UPDATE requests if needed.
		//
		$this->answer       = array();
		$this->authority    = array();
		$this->additional   = array();

		return true;
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
