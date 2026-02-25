<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 * See LICENSE for more details.
 */

/**
 * NS Resource Record - RFC1035 section 3.3.11
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   NSDNAME                     /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class Net_DNS2_RR_NS extends Net_DNS2_RR
{
    public string $nsdname = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->cleanString($this->nsdname) . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->nsdname = $this->cleanString(array_shift($rdata));
        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $offset = $packet->offset;
            $this->nsdname = Net_DNS2_Packet::expand($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if (strlen($this->nsdname) > 0) {

            return $packet->compress($this->nsdname, $packet->offset);
        }

        return null;
    }
}
