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
 * @since     1.4.1
 *
 */

namespace NetDNS2\RR;

/**
 * CSYNC Resource Record - RFC 7477 seciond 2.1.1
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                  SOA Serial                   |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    Flags                      |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                 Type Bit Map                  /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
final class CSYNC extends \NetDNS2\RR
{
    /**
     * serial number
     */
    protected string $serial;

    /**
     * flags
     */
    protected int $flags;

    /**
     * array of RR type names
     *
     * @var array<int,string>
     */
    protected array $type_bit_maps = [];

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->serial . ' ' . $this->flags . ' ' . implode(' ', $this->type_bit_maps);
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->serial = $this->sanitize(array_shift($_rdata));
        $this->flags  = intval($this->sanitize(array_shift($_rdata)));

        foreach($_rdata as $data)
        {
            $this->type_bit_maps[] = strtoupper($this->sanitize($data));
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
            
        //
        // unpack the serial and flags values
        //
        $val = unpack('Nx/ny', $this->rdata);
        if ($val === false)
        {
            return false;
        }
        
        list('x' => $x, 'y' => $this->flags) = (array)$val;

        $this->serial = \NetDNS2\Client::expandUint32($x);

        //
        // parse out the RR bitmap                 
        //
        $this->type_bit_maps = \NetDNS2\BitMap::bitMapToArray(substr($this->rdata, 6));

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        //
        // pack the serial and flags values
        //
        $data = pack('Nn', $this->serial, $this->flags) . \NetDNS2\BitMap::arrayToBitMap($this->type_bit_maps);

        //
        // advance the offset
        //
        $_packet->offset += strlen($data);

        return $data;
    }
}
