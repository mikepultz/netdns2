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
 * DNSKEY Resource Record - RFC4034 sction 2.1
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              Flags            |    Protocol   |   Algorithm   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   /                                                               /
 *   /                            Public Key                         /
 *   /                                                               /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
class DNSKEY extends \NetDNS2\RR
{
    /**
     * flags
     */
    protected int $flags;

    /**
     * protocol
     */
    protected int $protocol;

    /**
     * algorithm used
     */
    protected int $algorithm;

    /**
     * the public key
     */
    protected string $key;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->flags . ' ' . $this->protocol . ' ' . $this->algorithm . ' ' . $this->key;
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->flags     = intval($this->sanitize(array_shift($_rdata)));
        $this->protocol  = intval($this->sanitize(array_shift($_rdata)));
        $this->algorithm = intval($this->sanitize(array_shift($_rdata)));
        $this->key       = implode(' ', $_rdata);
    
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
        // unpack the flags, protocol and algorithm
        //
        $val = unpack('nx/Cy/Cz', $this->rdata);
        if ($val === false)
        {
            return false;
        }

        list('x' => $this->flags, 'y' => $this->protocol, 'z' => $this->algorithm) = (array)$val;

        //
        // get the key
        //
        $this->key = base64_encode(substr($this->rdata, 4));

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if (strlen($this->key) == 0)
        {
            return '';
        }

        $data = pack('nCC', $this->flags, $this->protocol, $this->algorithm);

        $decode = base64_decode($this->key);
        if ($decode !== false)
        {
            $data .= $decode;
        }

        $_packet->offset += strlen($data);

        return $data;
    }
}
