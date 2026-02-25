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
class Net_DNS2_RR_TALINK extends Net_DNS2_RR
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
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $offset = $packet->offset;

            $this->previous = Net_DNS2_Packet::label($packet, $offset);
            $this->next     = Net_DNS2_Packet::label($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
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
