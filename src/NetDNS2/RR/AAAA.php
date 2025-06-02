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
 * A Resource Record - RFC1035 section 3.4.1
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                                               |       
 *    |                                               |       
 *    |                                               |       
 *    |                    ADDRESS                    |       
 *    |                                               |       
 *    |                   (128 bit)                   |       
 *    |                                               |       
 *    |                                               |       
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
final class AAAA extends \NetDNS2\RR
{
    /**
     * the IPv6 address in the preferred hexadecimal values of the eight 16-bit pieces per RFC1884
     */
    protected \NetDNS2\Data\IPv6 $address;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return strval($this->address);
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->address = new \NetDNS2\Data\IPv6(array_shift($_rdata) ?? '');

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrSet();
     */
    protected function rrSet(\NetDNS2\Packet &$_packet): bool
    {
        if ($this->rdlength != 16)
        {
            return false;
        }

        $offset = 0;

        $this->address = new \NetDNS2\Data\IPv6($this->rdata, $offset);

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        return $this->address->encode($_packet->offset);
    }
}
