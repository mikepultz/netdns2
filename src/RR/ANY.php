<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * This is only used for generating an empty ANY RR.
 */
class ANY extends RR
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
        return '';
    }
}
