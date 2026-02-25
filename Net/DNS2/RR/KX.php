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
 * KX Resource Record - RFC2230 section 3.1
 *
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                  PREFERENCE                   |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   /                   EXCHANGER                   /
 *   /                                               /
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class Net_DNS2_RR_KX extends Net_DNS2_RR
{
    public int $preference = 0;
    public string $exchange = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->preference . ' ' . $this->cleanString($this->exchange) . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->preference = (int) array_shift($rdata);
        $this->exchange   = $this->cleanString(array_shift($rdata));

        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('npreference', $this->rdata);
            $this->preference = $x['preference'];

            $offset = $packet->offset + 2;
            $this->exchange = Net_DNS2_Packet::label($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if (strlen($this->exchange) > 0) {
            $data = pack('nC', $this->preference, strlen($this->exchange)) .
                $this->exchange;

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
