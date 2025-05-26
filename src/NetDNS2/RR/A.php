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
 *    |                    ADDRESS                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
final class A extends \NetDNS2\RR
{
    /**
     * The IPv4 address in quad-dotted notation
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
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->address = $this->sanitize(array_shift($_rdata));

        if (\NetDNS2\Client::isIPv4($this->address) == false)
        {
            throw new \NetDNS2\Exception('address provided is not a valid IPv4 address: ' . $this->address, \NetDNS2\ENUM\Error::PARSE_ERROR);
        }

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrSet()
     */
    protected function rrSet(\NetDNS2\Packet &$_packet): bool
    {
        if ($this->rdlength != 4)
        {
            return false;
        }

        $val = inet_ntop($this->rdata);
        if ($val !== false)
        {
            $this->address = strval($val);
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
            $_packet->offset += 4;
            return strval($val);
        }

        return '';
    }
}
