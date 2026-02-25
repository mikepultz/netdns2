<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   Net_DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 */

/**
 * CSYNC Resource Record - RFC7477 section 2.1.1
 */
class Net_DNS2_RR_CSYNC extends Net_DNS2_RR
{
    public int|string $serial = 0;
    public int $flags = 0;

    /** @var array<int, string> */
    public array $type_bit_maps = [];

    #[\Override]
    protected function rrToString(): string
    {
        $out = $this->serial . ' ' . $this->flags;

        foreach ($this->type_bit_maps as $rr) {
            $out .= ' ' . strtoupper($rr);
        }

        return $out;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->serial   = array_shift($rdata);
        $this->flags    = (int) array_shift($rdata);

        $this->type_bit_maps = $rdata;

        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('@' . $packet->offset . '/Nserial/nflags', $packet->rdata);

            $this->serial   = Net_DNS2::expandUint32($x['serial']);
            $this->flags    = $x['flags'];

            $this->type_bit_maps = Net_DNS2_BitMap::bitMapToArray(
                substr($this->rdata, 6)
            );

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        $data = pack('Nn', $this->serial, $this->flags);

        $data .= Net_DNS2_BitMap::arrayToBitMap($this->type_bit_maps);

        $packet->offset += strlen($data);

        return $data;
    }
}
