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
final class IPv4 extends \NetDNS2\Data
{
    public function __construct(mixed $_data = null, ?int &$_offset = null)
    {
        parent::__construct(self::DATA_TYPE_IPV4, $_data, $_offset);
    }

    /**
      * encode the stored value and return it
      *
      */
    public function encode(?int &$_offset = null): string
    {
        $val = inet_pton($this->m_value);
        if ($val !== false)        
        {
            $_offset += 4;
            return strval($val);
        }

        return '';
    }

    /**
      * decode the value provided and store it locally
      *
      */
    protected function decode(string $_rdata, int &$_offset): void
    {
        $val = inet_ntop(substr($_rdata, $_offset, 4));
        if ($val !== false)
        {
            if (\NetDNS2\Client::isIPv4($val) == false)
            {
                throw new \NetDNS2\Exception(sprintf('invalid IPv4 address: %s', $val), \NetDNS2\ENUM\Error::INT_INVALID_IPV4);
            }

            $this->m_value = strval($val);
            $_offset += 4;
            return;
        }
    }
}
