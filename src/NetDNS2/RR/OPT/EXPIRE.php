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
 * RFC 7314 - Extension Mechanisms for DNS (EDNS) EXPIRE Option
 */
final class EXPIRE extends \NetDNS2\RR\OPT
{
    /**
     * the expire value (4 bytes)
     */
    protected int $expire = 0;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->option_code->label() . ' ' . $this->option_length . ' ' . $this->timeout;
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

        $val = unpack('Nx', $this->option_data);
        if ($val === false)
        {
            return false;
        }

        list('x' => $this->expire) = (array)$val;

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        //
        // build and add the local data
        //
        if ($this->expire > 0)
        {
            $this->option_length = 4;
            $this->option_data   = pack('N', $this->expire);
        } else
        {
            $this->option_length = 0;
            $this->option_data   = '';
        }

        //
        // build the parent OPT data
        //
        return parent::rrGet($_packet);
    }
}
