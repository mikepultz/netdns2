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
 * PX Resource Record - RFC2163 section 4
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                  PREFERENCE                   |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                    MAP822                     /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                    MAPX400                    /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--
 *
 */
final class PX extends \NetDNS2\RR
{
    /**
     * preference
     */
    protected int $preference;

    /**
     * the RFC822 part of the MCGAM
     */
    protected \NetDNS2\Data\Domain $map822;

    /**
     * the X.400 part of the MCGAM
     */
    protected \NetDNS2\Data\Domain $mapx400;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->preference . ' ' . $this->map822 . '. ' . $this->mapx400 . '.';
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->preference = intval($this->sanitize(array_shift($_rdata)));

        $this->map822  = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC2535, array_shift($_rdata));
        $this->mapx400 = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC2535, array_shift($_rdata));

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
        // parse the preference
        //
        $val = unpack('nx', $this->rdata);
        if ($val === false)
        {
            return false;
        }

        list('x' => $this->preference) = (array)$val;
            
        //
        // expand the two domain names
        //
        $offset = $_packet->offset + 2;

        $this->map822  = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC2535, $_packet, $offset);
        $this->mapx400 = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC2535, $_packet, $offset);

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if ($this->map822->length() == 0)
        {
            return '';
        }

        $_packet->offset += 2;

        return pack('n', $this->preference) . $this->map822->encode($_packet->offset) . $this->mapx400->encode($_packet->offset);
    }
}
