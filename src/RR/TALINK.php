<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * TALINK Resource Record - DNSSEC Trust Anchor
 *
 * http://tools.ietf.org/id/draft-ietf-dnsop-dnssec-trust-history-00.txt
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   PREVIOUS                    /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                     NEXT                      /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class TALINK extends RR
{
    public string $previous = '';
    public string $next = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->cleanString($this->previous) . '. ' .
            $this->cleanString($this->next) . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->previous = $this->cleanString($rdata[0]);
        $this->next     = $this->cleanString($rdata[1]);

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $offset = $packet->offset;

            $this->previous = Packet::label($packet, $offset);
            $this->next     = Packet::label($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if ((strlen($this->previous) > 0) || (strlen($this->next) > 0)) {

            $data = chr(strlen($this->previous)) . $this->previous .
                chr(strlen($this->next)) . $this->next;

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
