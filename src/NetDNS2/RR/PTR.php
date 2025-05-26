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
 * PTR Resource Record - RFC1035 section 3.3.12
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   PTRDNAME                    /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
final class PTR extends \NetDNS2\RR
{
    /**
     * the hostname of the PTR entry
     */
    private \NetDNS2\Data\Domain $ptrdname;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->ptrdname . '.';
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->ptrdname = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC1035, array_shift($_rdata));
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

        $this->ptrdname = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC1035, $_packet, $offset);

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        return $this->ptrdname->encode($_packet->offset);
    }
}
