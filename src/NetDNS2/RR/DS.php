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
 * DS Resource Record - RFC4034 sction 5.1
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           Key Tag             |  Algorithm    |  Digest Type  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   /                                                               /
 *   /                            Digest                             /
 *   /                                                               /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
class DS extends \NetDNS2\RR
{
    /**
     * key tag
     */
    protected int $keytag;

    /**
     * algorithm number
     */
    protected \NetDNS2\ENUM\DNSSEC\Algorithm $algorithm;

    /**
     * algorithm used to construct the digest
     */
    protected \NetDNS2\ENUM\DNSSEC\Digest $digesttype;

    /**
     * the digest data
     */
    protected string $digest;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->keytag . ' ' . $this->algorithm->value . ' ' . $this->digesttype->value . ' ' . $this->digest;
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->keytag     = intval($this->sanitize(array_shift($_rdata)));
        $this->algorithm  = \NetDNS2\ENUM\DNSSEC\Algorithm::set(intval($this->sanitize(array_shift($_rdata))));
        $this->digesttype = \NetDNS2\ENUM\DNSSEC\Digest::set(intval($this->sanitize(array_shift($_rdata))));
        $this->digest     = $this->sanitize(implode('', $_rdata));

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
        // unpack the keytag, algorithm and digesttype
        //
        $val = unpack('nw/Cx/Cy/H*z', $this->rdata);
        if ($val === false)
        {
            return false;
        }

        list('w' => $this->keytag, 'x' => $algorithm, 'y' => $digesttype, 'z' => $this->digest) = (array)$val;

        $this->algorithm  = \NetDNS2\ENUM\DNSSEC\Algorithm::set($algorithm);
        $this->digesttype = \NetDNS2\ENUM\DNSSEC\Digest::set($digesttype);

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if (strlen($this->digest) == 0)
        {
            return '';
        }
        
        $_packet->offset += strlen($this->digest) + 4;

        return pack('nCCH*', $this->keytag, $this->algorithm->value, $this->digesttype->value, $this->digest);
    }
}
