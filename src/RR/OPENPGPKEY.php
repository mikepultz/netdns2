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
 * OPENPGPKEY Resource Record - https://tools.ietf.org/html/draft-ietf-dane-openpgpkey-01
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   /                                                               /
 *   /                  OpenPGP Public KeyRing                       /
 *   /                                                               /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class OPENPGPKEY extends RR
{
    public string $key = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->key;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->key = array_shift($rdata);

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $this->key = base64_encode(substr($this->rdata, 0, $this->rdlength));

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->key) > 0) {

            $data = base64_decode($this->key);

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
