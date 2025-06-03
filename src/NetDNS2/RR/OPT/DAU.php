<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2025, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   NetDNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2025 Mike Pultz <mike@mikepultz.com>
 * @license   https://opensource.org/license/bsd-3-clause/ BSD-3-Clause
 * @link      https://netdns2.com/
 * @since     1.6.0
 *
 */

namespace NetDNS2\RR\OPT;

/**
 * RFC 6875 - Signaling Cryptographic Algorithm Understanding in DNS Security Extensions (DNSSEC)
 *
 *  0                       8                      16
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                  OPTION-CODE                  |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                  LIST-LENGTH                  |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |       ALG-CODE        |        ...            /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
class DAU extends \NetDNS2\RR\OPT
{
    /**
     * list of assigned values of DNSSEC zone signing algorithms, DS hash algorithms, or NSEC3 hash algorithms (depending
     * on the OPTION-CODE in use) that the client declares to be supported.
     *
     * @var array<int>
     */
    protected array $alg_code = [];

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->option_code->label() . ' ' . $this->option_length . ' ' . implode(' ', $this->alg_code);
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     */
    protected function rrFromString(array $_rdata): bool
    {
        return true;
    }

    /**
     * @see \NetDNS2\RR::rrSet()
     */
    protected function rrSet(\NetDNS2\Packet &$_packet): bool
    {
        if ($this->option_length == 0)
        {            
            return true;
        }

        $val = unpack('C*', $this->option_data);
        if ($val == false)
        {
            return false;
        }

        foreach($val as $alg_code)
        {
            $this->alg_code[] = $alg_code;
        }

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if (count($this->alg_code) > 0)
        {
            $this->option_data   = pack('C*', ...$this->alg_code);
            $this->option_length = count($this->alg_code);
        } else
        {
            $this->option_data   = '';
            $this->option_length = 0;
        }

        //
        // build the parent OPT data
        //
        return parent::rrGet($_packet);        
    }
}
