<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * EID Resource Record - undefined; the rdata is simply used as-is in its
 * binary format, so no processing has to be done.
 */
class EID extends RR
{
    #[\Override]
    protected function rrToString(): string
    {
        return '';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        return true;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        return $this->rdata;
    }
}
