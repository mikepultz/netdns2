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
    protected string $address;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->address;
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     * @throws \NetDNS2\Exception
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->address = $this->sanitize(array_shift($_rdata));

        if (\NetDNS2\Client::isIPv6($this->address) == false)
        {
            throw new \NetDNS2\Exception('address provided is not a valid IPv6 address: ' . $this->address, \NetDNS2\ENUM\Error::PARSE_ERROR);            
        }

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrSet();
     */
    protected function rrSet(\NetDNS2\Packet &$_packet): bool
    {
        //
        // must be 8 x 16bit chunks, or 16 x 8bit
        //
        if ($this->rdlength != 16)
        {
            return false;
        }

        //
        // PHP's inet_ntop returns IPv6 addresses in their compressed form, but we want to keep with 
        // the preferred standard, so we'll parse it manually.
        //
        $val = unpack('n8', $this->rdata);
        if ($val !== false)
        {
            $this->address = vsprintf('%x:%x:%x:%x:%x:%x:%x:%x', (array)$val);
            return true;
        }

        return false;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        $val = inet_pton($this->address);
        if ($val !== false)
        {
            $_packet->offset += 16;
            return strval($val);
        }

        return '';
    }
}
