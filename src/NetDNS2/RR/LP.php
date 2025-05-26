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
 * @since     1.3.1
 *
 */

namespace NetDNS2\RR;

/**
 * LP Resource Record - RFC6742 section 2.4
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Preference           |                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
 *  /                                                               /
 *  /                              FQDN                             /
 *  /                                                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
final class LP extends \NetDNS2\RR
{
    /**
     * The preference
     */
    protected int $preference;

    /**
     * The fdqn field
     */
    protected \NetDNS2\Data\Domain $fqdn;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->preference . ' ' . $this->fqdn . '.';
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->preference = intval($this->sanitize(array_shift($_rdata)));
        $this->fqdn       = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, array_shift($_rdata));

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

        $val = unpack('n', $this->rdata);
        if ($val === false)
        {
            return false;
        }        

        $this->preference = ((array)$val)[1];

        $offset = $_packet->offset + 2;

        $this->fqdn = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, $_packet, $offset);

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if ($this->fqdn->length() == 0)
        {
            return '';
        }

        $data = pack('n', $this->preference) . $this->fqdn->encode();

        $_packet->offset += strlen($data);

        return $data;
    }
}
