<?php

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   NetDNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 * @since     File available since Release 0.6.0
 *
 */

namespace NetDNS2\RR;

/**
 * SRV Resource Record - RFC2782
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   PRIORITY                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    WEIGHT                     |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                     PORT                      |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                    TARGET                     /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
class SRV extends \NetDNS2\RR
{
    /*
     * The priority of this target host.
     */
    public $priority;

    /*
     * a relative weight for entries with the same priority
     */
    public $weight;

    /*
      * The port on this target host of this service.
     */
    public $port;

    /*
      * The domain name of the target host
     */
    public $target;

    /**
     * method to return the rdata portion of the packet as a string
     *
     * @return  string
     * @access  protected
     *
     */
    protected function rrToString()
    {
        return $this->priority . ' ' . $this->weight . ' ' . 
            $this->port . ' ' . $this->cleanString($this->target) . '.';
    }

    /**
     * parses the rdata portion from a standard DNS config line
     *
     * @param array $rdata a string split line of values for the rdata
     *
     * @return boolean
     * @access protected
     *
     */
    protected function rrFromString(array $rdata)
    {
        $this->priority = $rdata[0];
        $this->weight   = $rdata[1];
        $this->port     = $rdata[2];

        $this->target   = $this->cleanString($rdata[3]);
        
        return true;
    }

    /**
     * parses the rdata of the \NetDNS2\Packet object
     *
     * @param \NetDNS2\Packet &$packet a \NetDNS2\Packet packet to parse the RR from
     *
     * @return boolean
     * @access protected
     *
     */
    protected function rrSet(\NetDNS2\Packet &$packet)
    {
        if ($this->rdlength > 0) {
            
            //
            // unpack the priority, weight and port
            //
            $x = unpack('npriority/nweight/nport', $this->rdata);

            $this->priority = $x['priority'];
            $this->weight   = $x['weight'];
            $this->port     = $x['port'];

            $offset         = $packet->offset + 6;
            $this->target   = \NetDNS2\Packet::expand($packet, $offset);

            return true;
        }
        
        return false;
    }

    /**
     * returns the rdata portion of the DNS packet
     *
     * @param \NetDNS2\Packet &$packet a \NetDNS2\Packet packet use for
     *                                 compressed names
     *
     * @return mixed                   either returns a binary packed
     *                                 string or null on failure
     * @access protected
     *
     */
    protected function rrGet(\NetDNS2\Packet &$packet)
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
