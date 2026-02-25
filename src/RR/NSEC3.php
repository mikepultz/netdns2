<?php declare(strict_types=1);

namespace Net\DNS2\RR;


use Net\DNS2\DNS2;
use Net\DNS2\BitMap;
use Net\DNS2\Packet\Packet;

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 * See LICENSE for more details.
 */

/**
 * NSEC3 Resource Record - RFC5155 section 3.2
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Hash Alg.   |     Flags     |          Iterations           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Salt Length  |                     Salt                      /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Hash Length  |             Next Hashed Owner Name            /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  /                         Type Bit Maps                         /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class NSEC3 extends RR
{
    public int $algorithm = 0;
    public int $flags = 0;
    public int $iterations = 0;
    public int $salt_length = 0;
    public string $salt = '';
    public int $hash_length = 0;
    public string $hashed_owner_name = '';
    public array $type_bit_maps = [];

    #[\Override]
    protected function rrToString(): string
    {
        $out = $this->algorithm . ' ' . $this->flags . ' ' . $this->iterations . ' ';

        // per RFC5155, the salt_length value isn't displayed, and if the salt
        // is empty, the salt is displayed as '-'
        if ($this->salt_length > 0) {
            $out .= $this->salt;
        } else {
            $out .= '-';
        }

        $out .= ' ' . $this->hashed_owner_name;

        foreach ($this->type_bit_maps as $rr) {
            $out .= ' ' . strtoupper($rr);
        }

        return $out;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->algorithm  = (int)array_shift($rdata);
        $this->flags      = (int)array_shift($rdata);
        $this->iterations = (int)array_shift($rdata);

        // an empty salt is represented as '-' per RFC5155 section 3.3
        $salt = array_shift($rdata);
        if ($salt === '-') {
            $this->salt_length = 0;
            $this->salt = '';
        } else {
            $this->salt_length = strlen(pack('H*', $salt));
            $this->salt = strtoupper($salt);
        }

        $this->hashed_owner_name = array_shift($rdata);
        $this->hash_length = strlen(base64_decode($this->hashed_owner_name));

        $this->type_bit_maps = $rdata;

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $x = unpack('Calgorithm/Cflags/niterations/Csalt_length', $this->rdata);

            $this->algorithm   = $x['algorithm'];
            $this->flags       = $x['flags'];
            $this->iterations  = $x['iterations'];
            $this->salt_length = $x['salt_length'];

            $offset = 5;

            if ($this->salt_length > 0) {
                $x = unpack('H*', substr($this->rdata, $offset, $this->salt_length));
                $this->salt = strtoupper($x[1]);
                $offset += $this->salt_length;
            }

            $x = unpack('@' . $offset . '/Chash_length', $this->rdata);
            $offset++;

            $this->hash_length = $x['hash_length'];
            if ($this->hash_length > 0) {
                $this->hashed_owner_name = base64_encode(
                    substr($this->rdata, $offset, $this->hash_length)
                );
                $offset += $this->hash_length;
            }

            $this->type_bit_maps = BitMap::bitMapToArray(
                substr($this->rdata, $offset)
            );

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        $salt = pack('H*', $this->salt);
        $this->salt_length = strlen($salt);

        $data = pack(
            'CCnC',
            $this->algorithm, $this->flags, $this->iterations, $this->salt_length
        );
        $data .= $salt;

        $data .= chr($this->hash_length);
        if ($this->hash_length > 0) {
            $data .= base64_decode($this->hashed_owner_name);
        }

        $data .= BitMap::arrayToBitMap($this->type_bit_maps);

        $packet->offset += strlen($data);

        return $data;
    }
}
