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
 * SRV Resource Record - RFC2782
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   PRIORITY                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    WEIGHT                     |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                     PORT                      |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                    TARGET                     /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
final class SRV extends \NetDNS2\RR
{
    /**
     * The priority of this target host.
     */
    protected int $priority;

    /**
     * a relative weight for entries with the same priority
     */
    protected int $weight;

    /**
     * The port on this target host of this service.
     */
    protected int $port;

    /**
     * The domain name of the target host
     */
    protected \NetDNS2\Data\Domain $target;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->priority . ' ' . $this->weight . ' ' . $this->port . ' ' . $this->target . '.';
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->priority = intval($this->sanitize(array_shift($_rdata)));
        $this->weight   = intval($this->sanitize(array_shift($_rdata)));
        $this->port     = intval($this->sanitize(array_shift($_rdata)));

        $this->target   = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC2535, array_shift($_rdata));
        
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

        $val = unpack('nx/ny/nz', $this->rdata);
        if ($val === false)
        {
            return false;
        }

        list('x' => $this->priority, 'y' => $this->weight, 'z' => $this->port) = (array)$val;

        $offset = $_packet->offset + 6;
            
        $this->target = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC2535, $_packet, $offset);

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if ($this->target->length() == 0)
        {
            return '';
        }

        $_packet->offset += 6;

        return pack('nnn', $this->priority, $this->weight, $this->port) . $this->target->encode($_packet->offset);
    }
}
