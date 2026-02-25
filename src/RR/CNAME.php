<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * CNAME Resource Record - RFC1035 section 3.3.1
 */
class CNAME extends RR
{
    public string $cname = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->cleanString($this->cname) . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->cname = $this->cleanString(array_shift($rdata));
        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $offset = $packet->offset;
            $this->cname = Packet::expand($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->cname) > 0) {
            return $packet->compress($this->cname, $packet->offset);
        }

        return null;
    }
}
