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
 * X25 Resource Record - RFC1183 section 3.1
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                  PSDN-address                 /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class Net_DNS2_RR_X25 extends Net_DNS2_RR
{
    public string $psdnaddress = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->formatString($this->psdnaddress);
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $data = $this->buildString($rdata);
        if (count($data) === 1) {
            $this->psdnaddress = $data[0];
            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $this->psdnaddress = Net_DNS2_Packet::label($packet, $packet->offset);
            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if (strlen($this->psdnaddress) > 0) {

            $data = chr(strlen($this->psdnaddress)) . $this->psdnaddress;

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
