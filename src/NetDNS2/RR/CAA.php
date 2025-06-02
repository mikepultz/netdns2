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
 * @since     1.2.0
 *
 */

namespace NetDNS2\RR;

/**
 * CAA Resource Record - http://tools.ietf.org/html/draft-ietf-pkix-caa-03
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |          FLAGS        |      TAG LENGTH       |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                      TAG                      /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                      DATA                     /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
final class CAA extends \NetDNS2\RR
{
    /**
     * The critcal flag
     */
    protected int $flags;

    /**
     * The tag length value
     */
    protected int $tag_length;

    /**
     * The property identifier
     */
    protected \NetDNS2\Data\Text $tag;

    /**
     * The property value
     */
    protected \NetDNS2\Data\Text $value;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->flags . ' ' . $this->tag . ' ' . \NetDNS2\RR::formatString($this->value->value());
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->flags = intval($this->sanitize(array_shift($_rdata)));
        $this->tag   = new \NetDNS2\Data\Text($this->sanitize(array_shift($_rdata)));
        $this->value = new \NetDNS2\Data\Text($this->sanitize(implode(' ', $_rdata), false));
        
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
        // unpack the flags and tag length
        //
        $val = unpack('Cx/Cy', $this->rdata);
        if ($val === false)
        {
            return false;
        }

        list('x' => $this->flags, 'y' => $this->tag_length) = (array)$val;

        //
        // extract the tag value
        //
        $this->tag = new \NetDNS2\Data\Text(substr($this->rdata, 2, $this->tag_length));

        //
        // extract the value;
        //
        $this->value = new \NetDNS2\Data\Text(substr($this->rdata, 2 + $this->tag_length));

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if ($this->value->length() == 0)
        {
            return '';
        }

        $_packet->offset += 2 + $this->tag->length() + $this->value->length();

        return pack('CC', $this->flags, $this->tag->length()) . $this->tag . $this->value;
    }
}
