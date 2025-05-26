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
 * RP Resource Record - RFC1183 section 2.2
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   mboxdname                   /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   txtdname                    /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
final class RP extends \NetDNS2\RR
{
    /**
     * mailbox for the responsible person
     */
    protected \NetDNS2\Data\Mailbox $mboxdname;

    /**
     * is a domain name for which TXT RR's exists
     */
    protected \NetDNS2\Data\Domain $txtdname;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->mboxdname->display() . '. ' . $this->txtdname . '.';
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->mboxdname = new \NetDNS2\Data\Mailbox(\NetDNS2\Data::DATA_TYPE_RFC2535, array_shift($_rdata));
        $this->txtdname  = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC2535, array_shift($_rdata));

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

        $this->mboxdname = new \NetDNS2\Data\Mailbox(\NetDNS2\Data::DATA_TYPE_RFC2535, $_packet, $offset);
        $this->txtdname  = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC2535, $_packet, $offset);

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        return $this->mboxdname->encode($_packet->offset) . $this->txtdname->encode($_packet->offset);
    }
}
