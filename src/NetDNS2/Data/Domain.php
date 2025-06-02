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
 * container to store domain names, encoded in different formats for wire/presentation
 */
final class Domain extends \NetDNS2\Data
{
    /**
      * encode the stored value and return it
      *
      * @throws \NetDNS2\Exception
      */
    public function encode(?int &$_offset = null): string
    {
        switch($this->m_type)
        {
            case self::DATA_TYPE_CANON:      return $this->encode_canonical($this->m_value);
            case self::DATA_TYPE_RFC1035:    return $this->encode_rfc1035($this->m_value, $_offset);
            case self::DATA_TYPE_RFC2535:    return $this->encode_rfc2535($this->m_value, $_offset);
            default:
                //
        }

        throw new \NetDNS2\Exception('invalid domain encoding type.', \NetDNS2\ENUM\Error::INT_PARSE_ERROR);
    }

    /**
      * decode the value provided and store it locally
      *
      */
    protected function decode(string $_rdata, int &$_offset): void
    {
        $this->m_value = implode('.', $this->_decode($_rdata, $_offset));
    }
}
