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
 * LP Resource Record - RFC6742 section 2.4
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Preference           |                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
 *  /                                                               /
 *  /                              FQDN                             /
 *  /                                                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class Net_DNS2_RR_LP extends Net_DNS2_RR
{
    public int $preference = 0;
    public string $fqdn = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->preference . ' ' . $this->fqdn . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->preference = (int) array_shift($rdata);
        $this->fqdn       = trim(array_shift($rdata), '.');

        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('npreference', $this->rdata);
            $this->preference = $x['preference'];
            $offset = $packet->offset + 2;

            $this->fqdn = Net_DNS2_Packet::expand($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if (strlen($this->fqdn) > 0) {
            $data = pack('n', $this->preference);
            $packet->offset += 2;

            $data .= $packet->compress($this->fqdn, $packet->offset);
            return $data;
        }

        return null;
    }
}
