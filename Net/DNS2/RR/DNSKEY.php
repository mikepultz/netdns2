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

//
// DNSKEY Resource Record - RFC4034 sction 2.1
//
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |              Flags            |    Protocol   |   Algorithm   |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   /                                                               /
//   /                            Public Key                         /
//   /                                                               /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
class Net_DNS2_RR_DNSKEY extends Net_DNS2_RR
{
	public $flags;
	public $protocol;
	public $algorithm;
	public $key;

	protected function _toString()
	{
		return $this->flags . ' ' . $this->protocol . ' ' . $this->algorithm . ' ' . $this->key;
	}
	protected function _fromString(array $rdata)
	{
		$this->flags 		= array_shift($rdata);
		$this->protocol		= array_shift($rdata);
		$this->algorithm	= array_shift($rdata);
		$this->key			= implode(' ', $rdata);
	
		return true;
	}
	protected function _set(Net_DNS2_Packet &$packet)
	{
		if ($this->rdlength > 0) {

			//
			// unpack the flags, protocol and algorithm
			//
			$x = unpack('nflags/Cprotocol/Calgorithm', $this->rdata);

			//
			// TODO: right now we're just displaying what's in DNS; we really shoudl be parsing
			// 		 bit 7 and bit 15 of the flags field, and store those separately.
			//
			//		 right now the DNSSEC implementation is really jsut for "display", we don't
			//		 validate or handle any of the keys
			//
			$this->flags		= $x['flags'];
			$this->protocol		= $x['protocol'];
			$this->algorithm	= $x['algorithm'];

			$this->key			= base64_encode(substr($this->rdata, 4));
		}

		return true;
	}
	protected function _get(Net_DNS2_Packet &$packet)
	{
		if (strlen($this->key) > 0) {

			$data = pack('nCC', $this->flags, $this->protocol, $this->algorithm);
			$data .= base64_decode($this->key);

			return $data;
		}
		
		return null;
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
