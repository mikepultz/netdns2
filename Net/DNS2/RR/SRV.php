<?php
/**
* Resolver library used to communicate with a DNS server.
*
* Module written by Mike Pultz <mike@mikepultz.com>
*
* Parts of this code was inspired by the PERL Net::DNS module by
* Michael Fuhr <mike@fuhr.org> and by the orginal Net_DNS PHP port by
* Eric Kilfoil <eric@ypass.net>
*
* PHP version >= 5.0.0
*
* LICENSE: This source file is subject to version 3.01 of the PHP license
* that is available through the world-wide-web at the following URI:
* http://www.php.net/license/3_01.txt.  If you did not receive a copy of
* the PHP License and are unable to obtain it through the web, please
* send a note to license@php.net so we can mail you a copy immediately.
*
* @category   Net
* @package    Net_DNS2
* @author     Mike Pultz <mike@mikepultz.com>
* @license    http://www.php.net/license/3_01.txt  PHP License 3.01
*/

//
// SRV Resource Record - RFC2782
//
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                   PRIORITY                    |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                    WEIGHT                     |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    |                     PORT                      |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    /                    TARGET                     /
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
class Net_DNS2_RR_SRV extends Net_DNS2_RR
{
	public $priority;
	public $weight;
	public $port;
	public $target;

	protected function _toString()
	{
		return $this->priority . ' ' . $this->weight . ' ' . $this->port . ' ' . $this->target . '.';
	}
	protected function _fromString(array $rdata)
	{
		$this->priority	= $rdata[0];
		$this->weight	= $rdata[1];
		$this->port		= $rdata[2];

		$this->target	= strtolower(trim($rdata[3], '.'));
		
		return true;
	}
	protected function _set(Net_DNS2_Packet &$packet)
	{
		if ($this->rdlength > 0) {
			
			//
			// unpack the priority, weight and port
			//
			$x = unpack('npriority/nweight/nport', $this->rdata);

			$this->priority = $x['priority'];
			$this->weight	= $x['weight'];
			$this->port 	= $x['port'];

			$offset 		= $packet->offset + 6;
			$this->target	= Net_DNS2_Packet::expand($packet, $offset);
		}
		
		return true;
	}
	protected function _get(Net_DNS2_Packet &$packet)
	{
		if (strlen($this->target) > 0) {

			$data = pack('nnn', $this->priority, $this->weight, $this->port);
			$packet->offset += 6;

			$data .= $packet->compress($this->target, $packet->offset);
			return $data;
		}

		return null;
	}
}

?>
