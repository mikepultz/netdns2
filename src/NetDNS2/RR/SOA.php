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
 * @since     0.6.0
 *
 */

namespace NetDNS2\RR;

/**
 * SOA Resource Record - RFC1035 section 3.3.13
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                     MNAME                     /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                     RNAME                     /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    SERIAL                     |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    REFRESH                    |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                     RETRY                     |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    EXPIRE                     |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    MINIMUM                    |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
final class SOA extends \NetDNS2\RR
{
    /**
     * The master DNS server
     */
    protected \NetDNS2\Data\Domain $mname;

    /**
     * mailbox of the responsible person
     */
    protected \NetDNS2\Data\Mailbox $rname;

    /**
     * serial number
     */
    protected string $serial;

    /**
     * refresh time
     */
    protected string $refresh;

    /**
     * retry interval
     */
    protected string $retry;

    /**
     * expire time
     */
    protected string $expire;

    /**
     * minimum TTL for any RR in this zone
     */
    protected string $minimum;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->mname . '. ' . $this->rname->display() . '. ' . $this->serial . ' ' . $this->refresh . ' ' . $this->retry . ' ' . $this->expire . ' ' . $this->minimum;
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->mname    = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC1035, array_shift($_rdata));
        $this->rname    = new \NetDNS2\Data\Mailbox(\NetDNS2\Data::DATA_TYPE_RFC1035, array_shift($_rdata));

        $this->serial   = $this->sanitize(array_shift($_rdata));
        $this->refresh  = $this->sanitize(array_shift($_rdata));
        $this->retry    = $this->sanitize(array_shift($_rdata));
        $this->expire   = $this->sanitize(array_shift($_rdata));
        $this->minimum  = $this->sanitize(array_shift($_rdata));

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

        $offset = $_packet->offset;

        //
        // parse the names
        //
        $this->mname = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC1035, $_packet, $offset);
        $this->rname = new \NetDNS2\Data\Mailbox(\NetDNS2\Data::DATA_TYPE_RFC1035, $_packet, $offset);

        //
        // get the SOA values
        //
        $val = unpack('Na/Nb/Nc/Nd/Ne/', $_packet->rdata, $offset);
        if ($val === false)
        {
            return false;
        }

        list('a' => $a, 'b' => $b, 'c' => $c, 'd' => $d, 'e' => $e) = (array)$val;

        $this->serial  = \NetDNS2\Client::expandUint32($a);
        $this->refresh = \NetDNS2\Client::expandUint32($b);
        $this->retry   = \NetDNS2\Client::expandUint32($c);
        $this->expire  = \NetDNS2\Client::expandUint32($d);
        $this->minimum = \NetDNS2\Client::expandUint32($e);

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        $data = $this->mname->encode($_packet->offset) . $this->rname->encode($_packet->offset) .
            pack('N5', $this->serial, $this->refresh, $this->retry, $this->expire, $this->minimum);

        $_packet->offset += 20;

        return $data;
    }
}
