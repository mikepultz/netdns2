<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * NS Resource Record - RFC1035 section 3.3.11
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   NSDNAME                     /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class NS extends RR
{
    public string $nsdname = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->cleanString($this->nsdname) . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->nsdname = $this->cleanString(array_shift($rdata));
        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $offset = $packet->offset;
            $this->nsdname = Packet::expand($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->nsdname) > 0) {

            return $packet->compress($this->nsdname, $packet->offset);
        }

        return null;
    }
}
