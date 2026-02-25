<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\DNS2;
use Net\DNS2\Packet\Packet;

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 */

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
