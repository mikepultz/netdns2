<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * DNAME Resource Record - RFC2672 section 3
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                     DNAME                     /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class DNAME extends RR
{
    public string $dname = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->cleanString($this->dname) . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->dname = $this->cleanString(array_shift($rdata));
        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $offset = $packet->offset;
            $this->dname = Packet::expand($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->dname) > 0) {
            return $packet->compress($this->dname, $packet->offset);
        }

        return null;
    }
}
