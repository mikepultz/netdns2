<?php declare(strict_types=1);

namespace Net\DNS2\RR;


use Net\DNS2\DNS2;
use Net\DNS2\Packet\Packet;

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 * See LICENSE for more details.
 */

/**
 * RT Resource Record - RFC1183 section 3.3
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                preference                     |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /             intermediate-host                 /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class RT extends RR
{
    public int $preference = 0;
    public string $intermediatehost = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->preference . ' ' .
            $this->cleanString($this->intermediatehost) . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->preference       = (int)$rdata[0];
        $this->intermediatehost = $this->cleanString($rdata[1]);

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $x = unpack('npreference', $this->rdata);

            $this->preference       = $x['preference'];
            $offset                 = $packet->offset + 2;

            $this->intermediatehost = Packet::expand($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->intermediatehost) > 0) {

            $data = pack('n', $this->preference);
            $packet->offset += 2;

            $data .= $packet->compress($this->intermediatehost, $packet->offset);

            return $data;
        }

        return null;
    }
}
