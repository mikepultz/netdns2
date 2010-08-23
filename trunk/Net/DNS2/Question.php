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
 * @version    SVN: $Id: Question.php 63 2010-08-23 05:35:49Z mike $
 * @link       http://pear.php.net/package/Net_DNS2
 * @since      File available since Release 1.0.0
 */

//
// DNS question format - RFC1035 section 4.1.2
//
//      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                                               |
//    /                     QNAME                     /
//    /                                               /
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                     QTYPE                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                     QCLASS                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
//
class Net_DNS2_Question
{
	public $qname;
	public $qtype;
	public $qclass;

	public function __construct(Net_DNS2_Packet &$packet = null)
	{
		if (!is_null($packet)) {

			$this->set($packet);
		} else {

			$this->qname 	= '';
			$this->qtype 	= 'A';
			$this->qclass 	= 'IN';
		}
	}
	public function string()
	{
		return ';;\n;; Question:\n;;\t ' . $this->qname . '. ' . $this->qtype . ' ' . $this->qclass . "\n";
	}
	public function set(Net_DNS2_Packet &$packet)
	{
		//
		// expand the name
		//
		$this->qname = $packet->expand($packet, $packet->offset);
		if ($packet->rdlength < ($packet->offset + 4)) {

			return false;
		}

		//
		// unpack the type and class
		//
		$type 			= ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);
		$class 			= ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);

		// TODO: validate the type/class and throw an exception if they're not found.

		$this->qtype 	= Net_DNS2_Lookups::$rr_types_by_id[$type];
		$this->qclass	= Net_DNS2_Lookups::$classes_by_id[$class];

		return true;
	}
	public function get(Net_DNS2_Packet &$packet, $offset)
	{
		// TODO: validate the type/class and throw an exception if they're not found.

		return $packet->compress($this->qname, $offset) . 
			pack('nn', Net_DNS2_Lookups::$rr_types_by_name[$this->qtype], Net_DNS2_Lookups::$classes_by_name[$this->qclass]);
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
