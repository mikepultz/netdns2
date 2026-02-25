<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 * See LICENSE for more details.
 */

/**
 * PTR Resource Record - RFC1035 section 3.3.12
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   PTRDNAME                    /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class Net_DNS2_RR_PTR extends Net_DNS2_RR
{
    public string $ptrdname = '';

    #[\Override]
    protected function rrToString(): string
    {
        return rtrim($this->ptrdname, '.') . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->ptrdname = rtrim(implode(' ', $rdata), '.');
        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $offset = $packet->offset;
            $this->ptrdname = Net_DNS2_Packet::expand($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if (strlen($this->ptrdname) > 0) {

            return $packet->compress($this->ptrdname, $packet->offset);
        }

        return null;
    }
}
