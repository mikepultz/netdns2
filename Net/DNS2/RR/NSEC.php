<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 * See LICENSE for more details.
 */

/**
 * NSEC Resource Record - RFC3845 section 2.1
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   /                      Next Domain Name                         /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   /                   List of Type Bit Map(s)                     /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class Net_DNS2_RR_NSEC extends Net_DNS2_RR
{
    public string $next_domain_name = '';
    public array $type_bit_maps = [];

    #[\Override]
    protected function rrToString(): string
    {
        $data = $this->cleanString($this->next_domain_name) . '.';

        foreach ($this->type_bit_maps as $rr) {
            $data .= ' ' . $rr;
        }

        return $data;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->next_domain_name = $this->cleanString(array_shift($rdata));
        $this->type_bit_maps = $rdata;

        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $offset = $packet->offset;
            $this->next_domain_name = Net_DNS2_Packet::expand($packet, $offset);

            $this->type_bit_maps = Net_DNS2_BitMap::bitMapToArray(
                substr($this->rdata, $offset - $packet->offset)
            );

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if (strlen($this->next_domain_name) > 0) {

            $data = $packet->compress($this->next_domain_name, $packet->offset);
            $bitmap = Net_DNS2_BitMap::arrayToBitMap($this->type_bit_maps);

            $packet->offset += strlen($bitmap);

            return $data . $bitmap;
        }

        return null;
    }
}
