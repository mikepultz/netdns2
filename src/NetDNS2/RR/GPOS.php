<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2025, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   NetDNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2025 Mike Pultz <mike@mikepultz.com>
 * @license   https://opensource.org/license/bsd-3-clause/ BSD-3-Clause
 * @link      https://netdns2.com/
 * @since     1.6.0
 *
 */

namespace NetDNS2\RR;

/**
 * GPOS Resource Record - RFC1712 section 3
 *
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *      |                   LONGITUDE                   |
 *      |                                               |
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *      |                   LATITUDE                    |
 *      |                                               |
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *      |                   ALTITUDE                    |
 *      |                                               |
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
final class GPOS extends \NetDNS2\RR
{
    /*
     * The longitude
     */
    protected \NetDNS2\Data\Text $longitude;

    /**
     * The latitude
     */
    protected \NetDNS2\Data\Text $latitude;

    /**
     * The altitude
     */
    protected \NetDNS2\Data\Text $altitude;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->longitude . ' ' . $this->latitude . ' ' . $this->altitude;
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     */
    protected function rrFromString(array $_rdata): bool
    {
        $data = $this->buildString($_rdata);

        if (count($data) > 0)
        {
            $this->longitude = new \NetDNS2\Data\Text(array_shift($data));
            $this->latitude  = new \NetDNS2\Data\Text(array_shift($data));
            $this->altitude  = new \NetDNS2\Data\Text(array_shift($data));
        }

        return true; 
    }

    /**
     * @see \NetDNS2\RR::rrSet()
     */
    protected function rrSet(\NetDNS2\Packet &$_packet): bool
    {
        if ($this->rdlength == 0)
        {
            return false;
        }

        $offset = $_packet->offset;
        $limit  = $offset + $this->rdlength;

        $this->longitude = new \NetDNS2\Data\Text($_packet->rdata, $offset);
        $this->latitude  = new \NetDNS2\Data\Text($_packet->rdata, $offset);
        $this->altitude  = new \NetDNS2\Data\Text($_packet->rdata, $offset);

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        return $this->longitude->encode() . $this->latitude->encode() . $this->altitude->encode();
    }
}
