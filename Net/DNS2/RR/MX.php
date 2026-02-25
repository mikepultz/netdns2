<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 * See LICENSE for more details.
 */

/**
 * MX Resource Record - RFC1035 section 3.3.9
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                  PREFERENCE                   |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   EXCHANGE                    /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class Net_DNS2_RR_MX extends Net_DNS2_RR
{
    public int $preference = 0;
    public string $exchange = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->preference . ' ' . $this->cleanString($this->exchange) . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->preference = (int)array_shift($rdata);
        $this->exchange   = $this->cleanString(array_shift($rdata));

        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $x = unpack('npreference', $this->rdata);
            $this->preference = $x['preference'];

            $offset = $packet->offset + 2;
            $this->exchange = Net_DNS2_Packet::expand($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if (strlen($this->exchange) > 0) {

            $data = pack('n', $this->preference);
            $packet->offset += 2;

            $data .= $packet->compress($this->exchange, $packet->offset);
            return $data;
        }

        return null;
    }
}
