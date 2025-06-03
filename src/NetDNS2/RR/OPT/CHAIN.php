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

namespace NetDNS2\RR\OPT;

/**
 * RFC 7901 - CHAIN Query Requests in DNS
 *
 *
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-------------------------------+-------------------------------+
 * !         OPTION-CODE           !         OPTION-LENGTH         !
 * +-------------------------------+-------------------------------+
 * ~                Closest Trust Point (FQDN)                     ~
 * +---------------------------------------------------------------+
 *
 */
final class CHAIN extends \NetDNS2\RR\OPT
{
    /**
     * closest trust point; This entry is the "lowest" known entry in the DNS chain known by the recursive server seeking 
     * a CHAIN answer for which it has a validated Delegation Signer (DS) and DNSKEY record
     */
    protected \NetDNS2\Data\Domain $closest_trust_point;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->option_code->label() . ' ' . $this->option_length . ' ' . $this->closest_trust_point . '.';
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     */
    protected function rrFromString(array $_rdata): bool
    {
        return true;
    }

    /**
     * @see \NetDNS2\RR::rrSet()
     */
    protected function rrSet(\NetDNS2\Packet &$_packet): bool
    {
        $offset = 0;
        $this->closest_trust_point = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, $this->option_data, $offset);

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        $this->option_data   = $this->closest_trust_point->encode();
        $this->option_length = strlen($this->option_data);

        //
        // build the parent OPT data
        //
        return parent::rrGet($_packet);        
    }
}
