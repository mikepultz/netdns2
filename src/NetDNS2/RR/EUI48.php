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
 * @since     1.3.2
 *
 */

namespace NetDNS2\RR;

/**
 * EUI48 Resource Record - RFC7043 section 3.1
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          EUI-48 Address                       |
 * |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
final class EUI48 extends \NetDNS2\RR
{
    /**
     * The EUI48 address, in hex format
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
     */
    protected function rrFromString(array $_rdata): bool
    {
        $value = $this->sanitize(array_shift($_rdata));

        //
        // re: RFC 7043, the field must be represented as six two-digit hex numbers separated by hyphens.
        //
        $a = explode('-', $value);
        if (count($a) != 6)
        {
            return false;
        }

        //
        // make sure they're all hex values
        //
        foreach($a as $i)
        {
            if (ctype_xdigit($i) == false)
            {
                return false;
            }
        }

        //
        // store it
        //
        $this->address = $value;

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

        $this->address = vsprintf('%02x-%02x-%02x-%02x-%02x-%02x', (array)unpack('C6', $this->rdata));
        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        $data = '';

        $a = explode('-', $this->address);
        foreach($a as $b)
        {
            $data .= chr(intval(hexdec($b)));
        }

        $_packet->offset += 6;

        return $data;
    }
}
