<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 * See LICENSE for more details.
 */

/**
 * RP Resource Record - RFC1183 section 2.2
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   mboxdname                   /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   txtdname                    /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class Net_DNS2_RR_RP extends Net_DNS2_RR
{
    public string $mboxdname = '';
    public string $txtdname = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->cleanString($this->mboxdname) . '. ' . $this->cleanString($this->txtdname) . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->mboxdname = $this->cleanString($rdata[0]);
        $this->txtdname  = $this->cleanString($rdata[1]);

        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $offset = $packet->offset;

            $this->mboxdname = Net_DNS2_Packet::expand($packet, $offset, true);
            $this->txtdname  = Net_DNS2_Packet::expand($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if (strlen($this->mboxdname) > 0) {

            return $packet->compress($this->mboxdname, $packet->offset) .
                $packet->compress($this->txtdname, $packet->offset);
        }

        return null;
    }
}
