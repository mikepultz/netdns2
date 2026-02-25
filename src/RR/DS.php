<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

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
class DS extends RR
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
    protected function rrSet(Packet &$packet): bool
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
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->digest) > 0) {
            $data = pack('nCCH*', $this->keytag, $this->algorithm, $this->digesttype, $this->digest);

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
