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
 * @since     1.5.3
 *
 */

namespace NetDNS2\RR;

/**
 *
 * ZONEMD Resource Record - RFC8976 section 2.2
 * 
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Serial                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Scheme     |Hash Algorithm |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
 * |                             Digest                            |
 * /                                                               /
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
final class ZONEMD extends \NetDNS2\RR
{
    /**
     * ZONEMD schemes - there is currently only one defined.
     */
    public const ZONEMD_SCHEME_SIMPLE  = 1;

    /**
     * ZONEMD hash algorithms
     */
    public const ZONEMD_HASH_ALGORITHM_SHA384  = 1;
    public const ZONEMD_HASH_ALGORITHM_SHA512  = 2;

    /**
     * the serial number from the zone's SOA record
     */
    protected int $serial;

    /**
     * the methods by which data is collated and presented as input to the hashing function.
     */
    protected int $scheme;

    /**
     * the cryptographic hash algorithm used to construct the digest.
     */
    protected int $hash_algorithm;

    /**
     * the output of the hash algorithm.
     */
    protected string $digest = '';

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->serial . ' ' . $this->scheme . ' ' . $this->hash_algorithm . ' ' . $this->digest;
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->serial           = intval($this->sanitize(array_shift($_rdata)));
        $this->scheme           = intval($this->sanitize(array_shift($_rdata)));
        $this->hash_algorithm   = intval($this->sanitize(array_shift($_rdata)));

        //
        // digest must be provided as hexadecimal
        //
        // bind presents this in uppercase, so we'll match that
        //
        $this->digest = strtoupper(implode('', $_rdata));

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
        // unpack the serial, scheme, and hash algorithm
        //
        $val = unpack('Nx/Cy/Cz', $this->rdata);
        if ($val === false)
        {
            return false;
        }

        list('x' => $this->serial, 'y' => $this->scheme, 'z' => $this->hash_algorithm) = $val;

        //
        // copy the digest
        //
        $val = unpack('H*', substr($this->rdata, 6, $this->rdlength - 6));
        if ($val === false)
        {
            return false;
        }

        //
        // digest must be provided as hexadecimal
        //
        // bind presents this in uppercase, so we'll match that
        //
        $this->digest = strtoupper(implode('', (array)$val));

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

        $digest = pack('H*', $this->digest);

        $_packet->offset = strlen($digest) + 6;

        return pack('NCC', $this->serial, $this->scheme, $this->hash_algorithm) . $digest;
    }
}
