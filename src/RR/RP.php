<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * RP Resource Record - RFC1183 section 2.2
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   mboxdname                   /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   txtdname                    /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class RP extends RR
{
    public string $mboxdname = '';
    public string $txtdname = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->cleanString($this->mboxdname) . '. ' . $this->cleanString($this->txtdname) . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->mboxdname = $this->cleanString($rdata[0]);
        $this->txtdname  = $this->cleanString($rdata[1]);

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $offset = $packet->offset;

            $this->mboxdname = Packet::expand($packet, $offset, true);
            $this->txtdname  = Packet::expand($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->mboxdname) > 0) {

            return $packet->compress($this->mboxdname, $packet->offset) .
                $packet->compress($this->txtdname, $packet->offset);
        }

        return null;
    }
}
