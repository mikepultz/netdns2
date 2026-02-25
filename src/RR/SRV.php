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
 * SRV Resource Record - RFC2782
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   PRIORITY                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    WEIGHT                     |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                     PORT                      |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                    TARGET                     /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class SRV extends RR
{
    public int $priority = 0;
    public int $weight = 0;
    public int $port = 0;
    public string $target = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->priority . ' ' . $this->weight . ' ' .
            $this->port . ' ' . $this->cleanString($this->target) . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->priority = (int)$rdata[0];
        $this->weight   = (int)$rdata[1];
        $this->port     = (int)$rdata[2];
        $this->target   = $this->cleanString($rdata[3]);

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $x = unpack('npriority/nweight/nport', $this->rdata);

            $this->priority = $x['priority'];
            $this->weight   = $x['weight'];
            $this->port     = $x['port'];

            $offset       = $packet->offset + 6;
            $this->target = Packet::expand($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->target) > 0) {

            $data = pack('nnn', $this->priority, $this->weight, $this->port);
            $packet->offset += 6;

            $data .= $packet->compress($this->target, $packet->offset);

            return $data;
        }

        return null;
    }
}
