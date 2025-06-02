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
final class IPv6 extends \NetDNS2\Data
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
            $_offset += 16;
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
        //
        // PHP's inet_ntop returns IPv6 addresses in their compressed form, but we want to keep with
        // the preferred standard, so we'll parse it manually.
        //
        $ar = unpack('n8', $_rdata, $_offset);
        if ($ar !== false)                
        {
            $val = vsprintf('%x:%x:%x:%x:%x:%x:%x:%x', (array)$ar);

            if (\NetDNS2\Client::isIPv6($val) == false)            
            {
                throw new \NetDNS2\Exception(sprintf('invalid IPv6 address: %s', $val), \NetDNS2\ENUM\Error::INT_INVALID_IPV6);                                  
            }

            $this->m_value = $val;
            $_offset += 16;

            return;
        }
    }
}
