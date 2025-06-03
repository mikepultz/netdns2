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

namespace NetDNS2\Data;

/**
 * container to store mailbox values used by some RRs (SOA, RP)
 *
 * the mailbox value is stored as an email address (with an @ symbol), but converted to wire format
 * on the way in/out.
 *
 * this also support escaping periods in email addresses.
 *
 */
final class Mailbox extends \NetDNS2\Data
{
    /**
      * encode the stored value and return it
      *
      * @throws \NetDNS2\Exception
      */
    public function encode(?int &$_offset = null): string
    {
        //
        // format the current value
        //
        $value = $this->email_to_mbox($this->m_value);

        switch($this->m_type)
        {
            case self::DATA_TYPE_RFC1035:    return $this->encode_rfc1035($value, $_offset);
            case self::DATA_TYPE_RFC2535:    return $this->encode_rfc2535($value, $_offset);
            default:
                //
        }

        throw new \NetDNS2\Exception('invalid mailbox encoding type.', \NetDNS2\ENUM\Error::INT_PARSE_ERROR);    
    }

    /**
      * decode the value provided and store it locally
      *
      */
    protected function decode(string $_rdata, int &$_offset): void
    {
        $this->m_value = $this->mbox_to_email(implode('.', $this->_decode($_rdata, $_offset, true)));
    }

    /**
     * format the email address to a mbox style email
     */
    public function display(): string
    {
        return $this->email_to_mbox($this->m_value);
    }

    /**
     * format the mbox style to a real email address for storage
     */
    private function mbox_to_email(string $_mailbox): string
    {
        //
        // split on the first . found, but use a negative lookbehind to skip any escaped instances
        //
        $x = preg_split('/(?<!\\\)\./', strtolower($_mailbox), 2);
        if ($x === false)
        {
            return $_mailbox;
        }

        return str_replace('\.', '.', $x[0]) . '@' . $x[1];
    }

    /**
     * format the email address to a mbox style email
     */
    private function email_to_mbox(string $_mailbox): string
    {
        if (strpos($_mailbox, '@') === false)
        {
            return $_mailbox;
        }

        $x = explode('@', $_mailbox);

        return str_replace('.', '\.', $x[0]) . '.' . $x[1];
    }
}
