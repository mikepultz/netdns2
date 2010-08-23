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
// PX Resource Record - RFC2163 section 4
//
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                  PREFERENCE                   |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    /                    MAP822                     /
//    /                                               /
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    /                    MAPX400                    /
//    /                                               /
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--
//
class Net_DNS2_RR_PX extends Net_DNS2_RR
{
	public $preference;
	public $map822;
	public $mapx400;

	protected function _toString()
	{
		return $this->preference . ' ' . $this->map822 . '. ' . $this->mapx400 . '.';
	}
	protected function _fromString(array $rdata)
	{
		$this->preference 	= $rdata[0];
		$this->map822		= strtolower(trim($rdata[1], '.'));
		$this->mapx400		= strtolower(trim($rdata[2], '.'));

		return true;
	}
	protected function _set(Net_DNS2_Packet &$packet)
	{
		if ($this->rdlength > 0) {

			//
			// parse the preference
			//
			$x = unpack('npreference', $this->rdata);
			$this->preference = $x['preference'];

			$offset 		= $packet->offset + 2;

			$this->map822 	= Net_DNS2_Packet::expand($packet, $offset);
			$this->mapx400 	= Net_DNS2_Packet::expand($packet, $offset);
		}

		return true;
	}
	protected function _get(Net_DNS2_Packet &$packet)
	{
		if (strlen($this->map822) > 0) {
			
			$data = pack('n', $this->preference);
			$packet->offset += 2;

			$data .= $packet->compress($this->map822, $packet->offset);
			$data .= $packet->compress($this->mapx400, $packet->offset);

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
