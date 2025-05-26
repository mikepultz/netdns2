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
 * NSEC3PARAM Resource Record - RFC5155 section 4.2
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Hash Alg.   |     Flags     |          Iterations           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Salt Length  |                     Salt                      /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
final class NSEC3PARAM extends \NetDNS2\RR
{
    /**
     * Algorithm to use
     */
    protected int $algorithm;

    /**
     * flags
     */
    protected int $flags;

    /**
     *  defines the number of additional times the hash is performed.
     */
    protected int $iterations;

    /**
     * the length of the salt- not displayed
     */
    protected int $salt_length;

    /**
     * the salt
     */
    protected string $salt;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        $out = $this->algorithm . ' ' . $this->flags . ' ' . $this->iterations . ' ';

        //
        // per RFC5155, the salt_length value isn't displayed, and if the salt is empty, then  salt is displayed as "-"
        //        
        if ($this->salt_length > 0)
        {
            $out .= $this->salt;
        } else
        {
            $out .= '-';
        }
    
        return $out;
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->algorithm  = intval($this->sanitize(array_shift($_rdata)));
        $this->flags      = intval($this->sanitize(array_shift($_rdata)));
        $this->iterations = intval($this->sanitize(array_shift($_rdata)));

        $salt = $this->sanitize(array_shift($_rdata));

        if ($salt == '-')
        {
            $this->salt_length = 0;
            $this->salt = '';
        } else
        {
            $this->salt_length = strlen(pack('H*', $salt));
            $this->salt = strtoupper($salt);
        }
        
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

        $val = unpack('Cw/Cx/ny/Cz', $this->rdata);
        if ($val === false)
        {
            return false;
        }
            
        list('w' => $this->algorithm, 'x' => $this->flags, 'y' => $this->iterations, 'z' => $this->salt_length) = (array)$val;

        if ($this->salt_length > 0)
        {
            $val = unpack('H*', substr($this->rdata, 5, $this->salt_length));
            if ($val === false)
            {
                return false;
            }

            $this->salt = strtoupper(((array)$val)[1]);
        }

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        $salt = pack('H*', $this->salt);

        $_packet->offset += strlen($salt) + 5;

        return pack('CCnC', $this->algorithm, $this->flags, $this->iterations, strlen($salt)) . $salt;
    }
}
