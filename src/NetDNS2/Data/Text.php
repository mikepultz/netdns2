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
 * @since     1.6.0
 *
 */

namespace NetDNS2\Data;

/**
 * class for managing text strings in DNS RR objects
 */
final class Text extends \NetDNS2\Data
{
    public function __construct(mixed $_data = null, ?int &$_offset = null)
    {
        parent::__construct(self::DATA_TYPE_CANON, $_data, $_offset);
    }

    /**
      * encode the stored value and return it
      *
      */
    public function encode(?int &$_offset = null): string
    {
        return pack('Ca*', strlen($this->m_value), $this->m_value);
    }

    /**
      * decode the value provided and store it locally
      *
      */
    protected function decode(string $_rdata, int &$_offset): void
    {
        if ($_offset > strlen($_rdata))
        {
            return;
        }

        $len = ord($_rdata[$_offset++]);
        if ($len == 0)
        {
            return;
        }

        if ( ($len + $_offset) > strlen($_rdata))
        {
            $this->m_value = substr($_rdata, $_offset);
        } else
        {
            $this->m_value = substr($_rdata, $_offset, $len);
        }

        $_offset += $len;
    }
}
