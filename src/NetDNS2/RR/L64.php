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
 * @since     1.3.1
 *
 */

namespace NetDNS2\RR;

/**
 * L64 Resource Record - RFC6742 section 2.3
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Preference           |                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *  |                          Locator64                            |
 *  +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
final class L64 extends \NetDNS2\RR
{
    /**
     * The preference
     */
    protected int $preference;

    /**
     * The locator64 field
     */
    protected string $locator64;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->preference . ' ' . $this->locator64;
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->preference = intval($this->sanitize(array_shift($_rdata)));
        $this->locator64  = $this->sanitize(array_shift($_rdata));

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
        // unpack the values
        //
        $val = unpack('nx/n4y', $this->rdata);
        if ($val === false)
        {
            return false;
        }

        list('x' => $this->preference, 'y1' => $a, 'y2' => $b, 'y3' => $c, 'y4' => $d) = (array)$val;
 
        //
        // build the locator64
        //
        $this->locator64 = dechex($a) . ':' . dechex($b) . ':' . dechex($c) . ':' . dechex($d);
      
        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if (strlen($this->locator64) == 0)
        {
            return '';
        }
           
        //
        // break out the locator64
        //
        $n = explode(':', $this->locator64);

        //
        // increment the offset
        //
        $_packet->offset += 10;

        //
        // pack the data
        //
        return pack('n5', $this->preference, hexdec($n[0]), hexdec($n[1]), hexdec($n[2]), hexdec($n[3]));
    }
}
