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

/*
 * TSIG Resource Record - RFC 2845
 *
 *      0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     /                          algorithm                            /
 *     /                                                               /
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                          time signed                          |
 *     |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                               |              fudge            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |            mac size           |                               /
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
 *     /                              mac                              /
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |           original id         |              error            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |          other length         |                               /
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
 *     /                          other data                           /
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * @package     Net_DNS2
 * @author      Mike Pultz <mike@mikepultz.com>
 * @see         Net_DNS2_RR
 *
 */
class Net_DNS2_RR_TSIG extends Net_DNS2_RR
{
    /**
     * method to return the rdata portion of the packet as a string
     *
     * @return  string
     * @access  protected
     *
     */
	protected function _toString()
	{
		$out = $this->algorithm . '. ' . $this->time_signed . ' ' . $this->fudge . ' ' . $this->mac_size . ' ' .
			$this->mac . ' ' . $this->orignal_id . ' ' . $this->error . ' '. $this->other_length;

		if ($this->other_length > 0) {

			$out .= ' ' . $this->other_data;
		}

		return $out;
	}

    /**
     * parses the rdata portion from a standard DNS config line
     *
     * @param   array       $rdata  a string split line of values for the rdata
     * @return  boolean
     * @access  protected
     *
     */
	protected function _fromString(array $rdata)
	{
		//
		// the only value passed in is the key-
		//
		$this->key = preg_replace('/\s+/', '', array_shift($rdata));

		//
		// the rest of the data is set to default
		//
		$this->algorithm	= 'HMAC-MD5.SIG-ALG.REG.INT';
		$this->time_signed	= time();
		$this->fudge		= 300;
		$this->mac_size		= 0;
		$this->mac			= '';
		$this->orignal_id	= 0;
		$this->error		= 0;
		$this->other_length	= 0;
		$this->other_data	= '';

		//
		// per RFC 2845 section 2.3
		//
		$this->class		= 'ANY';
		$this->ttl		 	= 0;

		return true;
	}

    /**
     * parses the rdata of the Net_DNS2_Packet object
     *
     * @param   Net_DNS2_Packet $packet     a Net_DNS2_Packet packet to parse the RR from
     * @return  boolean
     * @access  protected
     * 
     */
	protected function _set(Net_DNS2_Packet &$packet)
	{
		if ($this->rdlength > 0) {

			$offset = 0;

			//
			// expand the algorithm
			//
			$this->algorithm = $packet->expand($packet, $offset);

			//
			// unpack time, fudge and mac_size
			//
			$x = unpack('@' . $offset. '/ntime_high/Ntime_low/nfudge/nmac_size', $this->rdata);

			$this->time_signed	= $x['time_low'];
			$this->fudge		= $x['fudge'];
			$this->mac_size		= $x['mac_size'];

			$offset += 10;

			//
			// copy out the mac
			//
			$this->mac = substr($this->rdata, $offset, $this->mac_size);
			$offset += $this->mac_size;

			//
			// unpack the original id, error, and other_length values
			//
			$x = unpack('noriginal_id/nerror/nother_length', $this->rdata);
		
			$this->original_id	= $x['original_id'];
			$this->error		= $x['error'];
			$this->other_length	= $x['other_length'];

			//
			// the only time there is actually any "other data", is when there's a BADTIME
			// error code.
			//
			// The other length should be 6, and the other data field includes the servers
			// current time - per RFC 2845 section 4.5.2
			//
			if ($this->error == Net_DNS2_Lookups::RCODE_BADTIME)
			{
				if ($this->other_length != 6) {

					return false;
				}

				//
				// other data is a 48bit timestamp
				//
				$x = unpack('nhigh/nlow', substr($this->rdata, $offset + 6, $this->other_length);
				$this->other_data = $x['low'];
			}

			return true;
		}

		return false;
	}

    /**
     * returns the rdata portion of the DNS packet
     * 
     * @param   Net_DNS2_Packet $packet     a Net_DNS2_Packet packet use for compressed names
     * @return  mixed                       either returns a binary packed string or null on failure
     * @access  protected
     * 
     */
	protected function _get(Net_DNS2_Packet &$packet)
	{
		if (strlen($this->key) > 0) {

			//
			//
			//

			//
			// compress the algorithm
			//
			$packet->offset = 0;
			$data = $packet->compress($this->algorithm, $packet->offset);

			//
			// pack the time, fudge and mac size
			//
			$data .= pack('nNnn', 0, $this->time_signed, $this->fudge, $this->mac_size);
			$data .= $this->mac;

			//
			// check the error and other_length
			//
			if ($this->error == Net_DNS2_Lookups::RCODE_BADTIME) {

				$this->other_length = strlen($this->other_data);
				if ($this->other_lenth != 6) {

					return null;
				}
			} else {

				$this->other_length = 0;
				$this->other_data = '';
			}

			//
			// pack the id, error and other_length
			//
			$data .= pack('nnn', $packet->header->id, $this->error, $this->other_length);

			if ($this->other_length > 0) {

				$data .= pack('nN', 0, $this->other_data);
			}

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
