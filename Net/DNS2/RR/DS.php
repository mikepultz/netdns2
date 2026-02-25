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
 * DS Resource Record - RFC4034 sction 5.1
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           Key Tag             |  Algorithm    |  Digest Type  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   /                                                               /
 *   /                            Digest                             /
 *   /                                                               /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class Net_DNS2_RR_DS extends Net_DNS2_RR
{
    public int $keytag = 0;
    public int $algorithm = 0;
    public int $digesttype = 0;
    public string $digest = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->keytag . ' ' . $this->algorithm . ' ' . $this->digesttype . ' ' . $this->digest;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->keytag     = (int) array_shift($rdata);
        $this->algorithm  = (int) array_shift($rdata);
        $this->digesttype = (int) array_shift($rdata);
        $this->digest     = implode('', $rdata);

        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('nkeytag/Calgorithm/Cdigesttype/H*digest', $this->rdata);

            $this->keytag     = $x['keytag'];
            $this->algorithm  = $x['algorithm'];
            $this->digesttype = $x['digesttype'];
            $this->digest     = $x['digest'];

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if (strlen($this->digest) > 0) {
            $data = pack('nCCH*', $this->keytag, $this->algorithm, $this->digesttype, $this->digest);

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
