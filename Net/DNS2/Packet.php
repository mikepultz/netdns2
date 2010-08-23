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

class Net_DNS2_Packet
{
	//
	// the full binary data for this packet
	//
	public $rdata;
	public $rdlength;

	//
	// the offset pointer used when building/parsing packets
	//
	public $offset;

	//
	// the DNS packet header
	//
	public $header;

	//
	// array of Net_DNS2_Question objects
	//
	public $question = array();

	//
	// array of Net_DNS2_RR Objects for Answers
	//
	public $answer = array();

	//
	// array of Net_DNS2_RR Objects for Authority
	//
	public $authority = array();

	//
	// array of Net_DNS2_RR Objects for Addtitional
	//
	public $additional = array();

	//
	// array of compressed labeles
	//
	private $_compressed = array();

	public function __toString()
	{
		$output = $this->header->string();

		foreach($this->question as $x) {

			$output .= $x->string();
		}
		foreach($this->answer as $x) {

			$output .= $x->string();
		}
		foreach($this->authority as $x) {

			$output .= $x->string();
		}
		foreach($this->additional as $x) {

			$output .= $x->string();
		}

		return $output;
	}
	public function get()
	{
		$data = $this->header->get();

		foreach($this->question as $x) {

			$data .= $x->get($this, strlen($data));
		}
		foreach($this->answer as $x) {

			$data .= $x->get($this, strlen($data));
		}
		foreach($this->authority as $x) {

			$data .= $x->get($this, strlen($data));
		}
		foreach($this->additional as $x) {

			$data .= $x->get($this, $strlen($data));
		}

		return $data;
	}
	public function compress($name, $offset)
	{
		$names = explode('.', $name);
		$compname = '';

		while(!empty($names)) {

			$dname = join('.', $names);

			if (isset($this->_compressed[$dname])) {

				$compname .= pack('n', 0xc000 | $this->_compressed[$dname]);
				break;
			}

			$this->_compressed[$dname] = $offset;

			$first = array_shift($names);
			$length = strlen($first);

			$compname .= pack('Ca*', $length, $first);
			$offset += $length + 1;
		}

		if (empty($names)) {
			$compname .= "\0";
		}

		return $compname;
	}
	public static function expand(Net_DNS2_Packet &$packet, &$offset)
	{
		$name = '';

		while(1) {
			if ($packet->rdlength < ($offset + 1)) {
				return null;
			}
			
			$xlen = ord($packet->rdata[$offset]);
			if ($xlen == 0) {

				++$offset;
				break;

			} else if (($xlen & 0xc0) == 0xc0) {
				if ($packet->rdlength < ($offset + 2)) {

					return null;
				}

				$ptr = ord($packet->rdata[$offset]) << 8 | ord($packet->rdata[$offset+1]);
				$ptr = $ptr & 0x3fff;

				$name2 = Net_DNS2_Packet::expand($packet, $ptr);
				if (is_null($name2)) {

					return null;
				}

				$name .= $name2;
				$offset += 2;
	
				break;
			} else {
				++$offset;

				if ($packet->rdlength < ($offset + $xlen)) {

					return null;
				}

				$elem = '';
				$elem = substr($packet->rdata, $offset, $xlen);
				$name .= $elem . '.';
				$offset += $xlen;
			}
		}

		return trim($name, '.');
	}
	public static function label(Net_DNS2_Packet &$packet, &$offset)
	{
		$name = '';

		if ($packet->rdlength < ($offset + 1)) {

			return null;
		}

		$xlen = ord($packet->rdata[$offset]);
		++$offset;

		if (($xlen + $offset) > $packet->rdlength) {

			$name = substr($packet->rdata, $offset);
			$offset = $packet->rdlength;
		} else {

			$name = substr($packet->rdata, $offset, $xlen);
			$offset += $xlen;
		}

		return $name;
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
