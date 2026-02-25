<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   Net_DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 */

/**
 * HINFO Resource Record - RFC1035 section 3.3.2
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                      CPU                      /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                       OS                      /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class Net_DNS2_RR_HINFO extends Net_DNS2_RR
{
    public string $cpu = '';
    public string $os = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->formatString($this->cpu) . ' ' . $this->formatString($this->os);
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $data = $this->buildString($rdata);
        if (count($data) === 2) {
            $this->cpu = trim($data[0], '"');
            $this->os  = trim($data[1], '"');

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $offset = $packet->offset;

            $this->cpu = Net_DNS2_Packet::label($packet, $offset);
            $this->os  = Net_DNS2_Packet::label($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if (strlen($this->cpu) > 0) {
            $data = pack('Ca*Ca*', strlen($this->cpu), $this->cpu, strlen($this->os), $this->os);

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
