<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 * See LICENSE for more details.
 */

/**
 * PX Resource Record - RFC2163 section 4
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                  PREFERENCE                   |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                    MAP822                     /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                    MAPX400                    /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--
 */
class Net_DNS2_RR_PX extends Net_DNS2_RR
{
    public int $preference = 0;
    public string $map822 = '';
    public string $mapx400 = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->preference . ' ' . $this->cleanString($this->map822) . '. ' .
            $this->cleanString($this->mapx400) . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->preference = (int)$rdata[0];
        $this->map822     = $this->cleanString($rdata[1]);
        $this->mapx400    = $this->cleanString($rdata[2]);

        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $x = unpack('npreference', $this->rdata);
            $this->preference = $x['preference'];

            $offset = $packet->offset + 2;

            $this->map822  = Net_DNS2_Packet::expand($packet, $offset);
            $this->mapx400 = Net_DNS2_Packet::expand($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if (strlen($this->map822) > 0) {

            $data = pack('n', $this->preference);
            $packet->offset += 2;

            $data .= $packet->compress($this->map822, $packet->offset);
            $data .= $packet->compress($this->mapx400, $packet->offset);

            return $data;
        }

        return null;
    }
}
