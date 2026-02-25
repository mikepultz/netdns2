<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 * See LICENSE for more details.
 */

/**
 * NSEC3PARAM Resource Record - RFC5155 section 4.2
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Hash Alg.   |     Flags     |          Iterations           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Salt Length  |                     Salt                      /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class Net_DNS2_RR_NSEC3PARAM extends Net_DNS2_RR
{
    public int $algorithm = 0;
    public int $flags = 0;
    public int $iterations = 0;
    public int $salt_length = 0;
    public string $salt = '';

    #[\Override]
    protected function rrToString(): string
    {
        $out = $this->algorithm . ' ' . $this->flags . ' ' . $this->iterations . ' ';

        // per RFC5155, the salt_length value isn't displayed, and if the salt
        // is empty, the salt is displayed as "-"
        if ($this->salt_length > 0) {
            $out .= $this->salt;
        } else {
            $out .= '-';
        }

        return $out;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->algorithm  = (int)array_shift($rdata);
        $this->flags      = (int)array_shift($rdata);
        $this->iterations = (int)array_shift($rdata);

        $salt = array_shift($rdata);
        if ($salt === '-') {
            $this->salt_length = 0;
            $this->salt = '';
        } else {
            $this->salt_length = strlen(pack('H*', $salt));
            $this->salt = strtoupper($salt);
        }

        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $x = unpack('Calgorithm/Cflags/niterations/Csalt_length', $this->rdata);

            $this->algorithm   = $x['algorithm'];
            $this->flags       = $x['flags'];
            $this->iterations  = $x['iterations'];
            $this->salt_length = $x['salt_length'];

            if ($this->salt_length > 0) {
                $x = unpack('H*', substr($this->rdata, 5, $this->salt_length));
                $this->salt = strtoupper($x[1]);
            }

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        $salt = pack('H*', $this->salt);
        $this->salt_length = strlen($salt);

        $data = pack(
            'CCnC',
            $this->algorithm, $this->flags, $this->iterations, $this->salt_length
        ) . $salt;

        $packet->offset += strlen($data);

        return $data;
    }
}
