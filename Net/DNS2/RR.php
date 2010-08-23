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
// DNS resource record format - RFC1035 section 4.1.3
//
//      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                                               |
//    /                                               /
//    /                      NAME                     /
//    |                                               |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                      TYPE                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                     CLASS                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                      TTL                      |
//    |                                               |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                   RDLENGTH                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//    /                     RDATA                     /
//    /                                               /
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
//
abstract class Net_DNS2_RR
{
	public $name;
	public $type;
	public $class;
	public $ttl;
	public $rdlength;
	public $rdata;

	//
	// abstract functions defined in sub-classes
	//
	abstract protected function _toString();
	abstract protected function _fromString(array $rdata);
	abstract protected function _set(Net_DNS2_Packet &$packet);
	abstract protected function _get(Net_DNS2_Packet &$packet);

	//
	// common functions
	//
	public function __construct(Net_DNS2_Packet &$packet = null, array $rr = null)
	{
		if ( (!is_null($packet)) && (!is_null($rr)) ) {

			$this->set($packet, $rr);
		} else {

			if (isset(Net_DNS2_Lookups::$rr_types_class_to_id[get_called_class()])) {

				$this->type	= Net_DNS2_Lookups::$rr_types_by_id[Net_DNS2_Lookups::$rr_types_class_to_id[get_called_class()]];
			}

			$this->class	= 'IN';
			$this->ttl		= 86400;
		}
	}
	public function __toString()
	{
		return $this->toString();
	}

	//
	// return a formatted string; if a string has spaces in it, then return it with double
	// quotes around it, otherwise, return it as it was passed in.
	//
	protected function _formatString($string)
	{
		//
		// make sure first it doesn't already have some
		//
		$s = trim($string, '"');

		if (preg_match('/\s+/', $s)) {
			return '"' . str_replace('"', '\"', $s) . '"';
		}
		
		return $s;
	}
	
	//
	// 
	//
	protected function _buildString(array $chunks)
	{
		$data = array();
		$c = 0;
		$in = false;

		foreach($chunks as $r) {

			if ( ($r[0] == '"') && ($r[strlen($r) - 1] == '"') && ($r[strlen($r) - 2] != '\\') ) {

				$data[$c] = $r;
				++$c;
				$in = false;

			} else if ($r[0] == '"') {

				$data[$c] = $r;
				$in = true;

			} else if ( ($r[strlen($r) - 1] == '"') && ($r[strlen($r) - 2] != '\\') ) {
            
				$data[$c] .= ' ' . $r;
				++$c;  
				$in = false;

			} else {

				if ($in == true)
					$data[$c] .= ' ' . $r;
				else
					$data[$c++] = $r;
			}
		}		

		foreach($data as $index => $string) {
			
			$data[$index] = str_replace('\"', '"', trim($string, '"'));
		}

		return $data;
	}

	public function set(Net_DNS2_Packet &$packet, array $rr)
	{
		$this->name 		= $rr['name'];
		$this->type 		= Net_DNS2_Lookups::$rr_types_by_id[$rr['type']];
		$this->class 		= Net_DNS2_Lookups::$classes_by_id[$rr['class']];
		$this->ttl 			= $rr['ttl'];
		$this->rdlength 	= $rr['rdlength'];
		$this->rdata 		= substr($packet->rdata, $packet->offset, $rr['rdlength']);

		return $this->_set($packet);
	}
	public function get(Net_DNS2_Packet &$packet)
	{
		$data = '';

		//
		// pack the name
		//
		$data = $packet->compress($this->name, $packet->offset);

		//
		// get the RR specific details
		//
		if ($this->rdlength == -1) {

			$this->rdlength = 0;
			$this->rdata 	= '';
		} else {

			$this->rdata 	= $this->_get($packet);
			$this->rdlength = strlen($this->rdata);
		}

		//
		// pack the rest of the values
		//
		$data .= pack('nnNn', 
			Net_DNS2_Lookups::$rr_types_by_name[$this->type], 
			Net_DNS2_Lookups::$classes_by_name[$this->class], 
			$this->ttl, 
			$this->rdlength);
		
		//
		// add the RR
		//
		$data .= $this->rdata;

		return $data;
	}
	public static function parse(Net_DNS2_Packet &$packet)
	{
		$object = array();

		//
		// expand the name
		//
		$object['name'] = $packet->expand($packet, $packet->offset);
		if (is_null($object['name'])) {

			// TODO: throw exception
			return null;
		}
		if ($packet->rdlength < ($packet->offset + 10)) {

			// TODO: throw exception
			return null;
		}

		//
		// unpack the RR details
		//
		$object['type']		= ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);
		$object['class']	= ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);

		$object['ttl']		= ord($packet->rdata[$packet->offset++]) << 24 | ord($packet->rdata[$packet->offset++]) << 16 | 
			ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);

		$object['rdlength']	= ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);


		if ($packet->rdlength < ($packet->offset + $object['rdlength'])) {
			return null;
		}

		//
		// lookup the class to use
		//
		$o = null;

		if (isset(Net_DNS2_Lookups::$rr_types_id_to_class[$object['type']])) {

			$class = Net_DNS2_Lookups::$rr_types_id_to_class[$object['type']];

			$o = new $class($packet, $object);
			if ($o) {

				$packet->offset += $object['rdlength'];
			}
		} else {
			// TODO: throw un-implemented RR exception
		}

		return $o;
	}

	//
	// format the display for this object
	//
	public function toString()
	{
		return $this->name . '. ' . $this->ttl . ' ' . $this->class . ' ' . $this->type . ' ' . $this->_toString();
	}

	//
	// parses a standard RR format lines, as defined by rfc1035 (kinda)
	//
	// In our implementation, the domain *must* be specified- format must be
	//
	//		<name> [<ttl>] [<class>] <type> <rdata>
	// or
	//		<name> [<class>] [<ttl>] <type> <rdata>
	//
	// name, title, class and type are parsed by this function, rdata is passed to the
	// RR specific classes for parsing.
	//
	public static function fromString($line)
	{
		if (strlen($line) == 0) {
			// TODO: throw exception;
		}

		$name 	= '';
		$type 	= '';
		$class	= 'IN';
		$ttl	= 86400;

		//
		// split the line by spaces
		//
		$values = preg_split('/[\s]+/', $line);
		if (count($values) < 3) {

			// TODO: throw execption- we should have at least three values
		}

		//
		// assume the first value is the name
		//
		$name = trim(strtolower(array_shift($values)), '.');

		//
		// The next value is either a TTL, Class or Type
		//
		foreach($values as $value) {

			switch($value) {
				case is_numeric($value):

					$ttl = array_shift($values);

				break;
				case isset(Net_DNS2_Lookups::$classes_by_name[strtoupper($value)]):

					$class = strtoupper(array_shift($values));

				break;
				case isset(Net_DNS2_Lookups::$rr_types_by_name[strtoupper($value)]):

					$type = strtoupper(array_shift($values));
					break 2;

				break;
				default:
					// TODO: throw execption; this shouldn't happen
			}
		}

		//
		// lookup the class to use
		//
		$o = null;

		if (isset(Net_DNS2_Lookups::$rr_types_id_to_class[Net_DNS2_Lookups::$rr_types_by_name[$type]])) {

			$o = new Net_DNS2_Lookups::$rr_types_id_to_class[Net_DNS2_Lookups::$rr_types_by_name[$type]];
			if ($o) {

				//
				// set the parsed values
				//
				$o->name 	= $name;
				$o->class	= $class;
				$o->ttl		= $ttl;
			
				//
				// parse the rdata
				//
				if ($o->_fromString($values) === false) {
					// TODO: throw exception
				}

			} else {
				// TODO: throw exception
			}

		} else {
			// TODO: throw un-implemented RR exception
		}

		return $o;
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
