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
 * L32 Resource Record - RFC6742 section 2.2
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Preference           |      Locator32 (16 MSBs)      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Locator32 (16 LSBs)       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
final class L32 extends \NetDNS2\RR
{
    /**
     * The preference
     */
    protected int $preference;

    /**
     * The locator32 field
     */
    protected string $locator32;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->preference . ' ' . $this->locator32;
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->preference = intval($this->sanitize(array_shift($_rdata)));
        $this->locator32  = $this->sanitize(array_shift($_rdata));

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
        $val = unpack('nx/C4y', $this->rdata);
        if ($val === false)
        {
            return false;
        }

        list('x' => $this->preference, 'y1' => $a, 'y2' => $b, 'y3' => $c, 'y4' => $d) = (array)$val;

        //
        // build the locator value
        //
        $this->locator32 = $a . '.' . $b . '.' . $c . '.' . $d;

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if (strlen($this->locator32) == 0)
        {
            return '';
        }
            
        //
        // increment the offset
        //
        $_packet->offset += 6;
        
        //
        // break out the locator value
        //
        $n = explode('.', $this->locator32);

        //
        // pack the data
        //
        return pack('nC4', $this->preference, $n[0], $n[1], $n[2], $n[3]);
    }
}
