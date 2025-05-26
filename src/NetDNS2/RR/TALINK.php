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
 * @since     1.2.0
 *
 */

namespace NetDNS2\RR;

/**
 * TALINK Resource Record - DNSSEC Trust Anchor
 *
 * http://tools.ietf.org/id/draft-ietf-dnsop-dnssec-trust-history-00.txt
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   PREVIOUS                    /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                     NEXT                      /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
final class TALINK extends \NetDNS2\RR
{
    /**
     * the previous domain name
     */
    protected \NetDNS2\Data\Domain $previous;

    /**
     * the next domain name
     */
    protected \NetDNS2\Data\Domain $next;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->previous . '. ' . $this->next . '.';
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->previous = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, array_shift($_rdata));
        $this->next     = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, array_shift($_rdata));

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

        $this->previous = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, $_packet->rdata, $offset);
        $this->next     = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, $_packet->rdata, $offset);

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        $data = $this->previous->encode() . $this->next->encode();

        $_packet->offset += strlen($data);

        return $data;
    }
}
