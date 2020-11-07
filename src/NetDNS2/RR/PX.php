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
 * PX Resource Record - RFC2163 section 4
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                  PREFERENCE                   |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                    MAP822                     /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                    MAPX400                    /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--
 *
 */
class PX extends \NetDNS2\RR
{
    /*
     * preference
     */
    public $preference;

    /* 
     * the RFC822 part of the MCGAM
     */
    public $map822;

    /*
     * the X.400 part of the MCGAM
     */
    public $mapx400;

    /**
     * method to return the rdata portion of the packet as a string
     *
     * @return  string
     * @access  protected
     *
     */
    protected function rrToString()
    {
        return $this->preference . ' ' . $this->cleanString($this->map822) . '. ' . 
            $this->cleanString($this->mapx400) . '.';
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
        $this->preference   = $rdata[0];
        $this->map822       = $this->cleanString($rdata[1]);
        $this->mapx400      = $this->cleanString($rdata[2]);

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
            // parse the preference
            //
            $x = unpack('npreference', $this->rdata);
            $this->preference = $x['preference'];

            $offset         = $packet->offset + 2;

            $this->map822   = \NetDNS2\Packet::expand($packet, $offset);
            $this->mapx400  = \NetDNS2\Packet::expand($packet, $offset);

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
