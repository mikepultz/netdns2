<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * NID Resource Record - RFC6742 section 2.1
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Preference           |                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *  |                             NodeID                            |
 *  +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class NID extends RR
{
    public int $preference = 0;
    public string $nodeid = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->preference . ' ' . $this->nodeid;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->preference = (int)array_shift($rdata);
        $this->nodeid     = array_shift($rdata);

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $x = unpack('npreference/n4nodeid', $this->rdata);

            $this->preference = $x['preference'];

            $this->nodeid = dechex($x['nodeid1']) . ':' .
                dechex($x['nodeid2']) . ':' .
                dechex($x['nodeid3']) . ':' .
                dechex($x['nodeid4']);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->nodeid) > 0) {

            $n = explode(':', $this->nodeid);

            return pack(
                'n5', $this->preference, hexdec($n[0]), hexdec($n[1]),
                hexdec($n[2]), hexdec($n[3])
            );
        }

        return null;
    }
}
