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
 * AFSDB Resource Record - RFC1183 section 1
 */
class Net_DNS2_RR_AFSDB extends Net_DNS2_RR
{
    public int $subtype = 0;
    public string $hostname = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->subtype . ' ' . $this->cleanString($this->hostname) . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->subtype  = (int) array_shift($rdata);
        $this->hostname = $this->cleanString(array_shift($rdata));

        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('nsubtype', $this->rdata);

            $this->subtype  = $x['subtype'];
            $offset         = $packet->offset + 2;

            $this->hostname = Net_DNS2_Packet::expand($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if (strlen($this->hostname) > 0) {
            $data = pack('n', $this->subtype);
            $packet->offset += 2;

            $data .= $packet->compress($this->hostname, $packet->offset);

            return $data;
        }

        return null;
    }
}
