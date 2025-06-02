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
 * RFC 8145 - Signaling Trust Anchor Knowledge in DNS Security Extensions (DNSSEC)
 *
 *   0                       8                      16
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                  OPTION-CODE                  |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                 OPTION-LENGTH                 |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    KEY-TAG                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                      ...                      /
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
final class KEYTAG extends \NetDNS2\RR\OPT
{
    /**
     * the list o fkey tag values
     *
     * @var array<int>
     */
    protected array $key_tag = [];

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->option_code->label() . ' ' . $this->option_length . ' ' . implode(' ', $this->key_tag);
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

        $val = unpack('n*', $this->option_data);
        if ($val == false)
        {
            return false;
        }

        foreach($val as $key_tag)
        {
            $this->key_tag[] = $key_tag;
        }

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if (count($this->key_tag) > 0)
        {
            $this->option_data   = pack('n*', ...$this->key_tag);
            $this->option_length = 2 * count($this->key_tag);
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
