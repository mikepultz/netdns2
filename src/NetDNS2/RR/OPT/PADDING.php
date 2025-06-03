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
 * RFC 7830 - The EDNS(0) Padding Option
 *
 * 0                       8                      16
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                  OPTION-CODE                  |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                 OPTION-LENGTH                 |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |        (PADDING) ...        (PADDING) ...     /
 * +-  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -
 *
 */
final class PADDING extends \NetDNS2\RR\OPT
{
    /**
     * padding value - should default to 0x00
     */
    protected string $padding = '';

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->option_code->label() . ' ' . $this->option_length;
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
            return false;
        }

        $val = unpack('H*', $this->option_data);
        if ($val === false)
        {
            return false;
        }

        $this->padding = implode('', $val);

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if (strlen($this->padding) > 0)
        {
            $this->option_data   = pack('H*', $this->padding);
            $this->option_length = strlen($this->option_data);
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
