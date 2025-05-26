<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2023, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   NetDNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2023 Mike Pultz <mike@mikepultz.com>
 * @license   https://opensource.org/license/bsd-3-clause/ BSD-3-Clause
 * @link      https://netdns2.com/
 * @since     0.6.0
 *
 */

namespace NetDNS2\RR;

/**
 * MX Resource Record - RFC1035 section 3.3.9
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                  PREFERENCE                   |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   EXCHANGE                    /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
final class MX extends \NetDNS2\RR
{
    /**
     * the preference for this mail exchanger
     */
    protected int $preference;

    /**
     * the hostname of the mail exchanger
     */
    protected \NetDNS2\Data\Domain $exchange;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->preference . ' ' . $this->exchange . '.';
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->preference = intval($this->sanitize(array_shift($_rdata)));
        $this->exchange   = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC1035, array_shift($_rdata));

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

        //
        // parse the preference
        //
        $val = unpack('nz', $this->rdata);
        if ($val === false)
        {
            return false;
        }

        list('z' => $this->preference) = (array)$val;

        //
        // get the exchange entry server)
        //
        $offset = $_packet->offset + 2;

        $this->exchange = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC1035, $_packet, $offset);

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        $_packet->offset += 2;

        return pack('n', $this->preference) . $this->exchange->encode($_packet->offset);
    }
}
