<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 * See LICENSE for more details.
 */

/**
 * NIMLOC Resource Record - undefined; the rdata is simply used as-is in its
 * binary format, so no processing has to be done.
 */
class Net_DNS2_RR_NIMLOC extends Net_DNS2_RR
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
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        return true;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        return $this->rdata;
    }
}
