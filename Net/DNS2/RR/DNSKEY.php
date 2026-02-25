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
 * DNSKEY Resource Record - RFC4034 sction 2.1
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              Flags            |    Protocol   |   Algorithm   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   /                                                               /
 *   /                            Public Key                         /
 *   /                                                               /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class Net_DNS2_RR_DNSKEY extends Net_DNS2_RR
{
    public int $flags = 0;
    public int $protocol = 0;
    public int $algorithm = 0;
    public string $key = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->flags . ' ' . $this->protocol . ' ' .
            $this->algorithm . ' ' . $this->key;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->flags     = (int) array_shift($rdata);
        $this->protocol  = (int) array_shift($rdata);
        $this->algorithm = (int) array_shift($rdata);
        $this->key       = implode(' ', $rdata);

        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('nflags/Cprotocol/Calgorithm', $this->rdata);

            $this->flags     = $x['flags'];
            $this->protocol  = $x['protocol'];
            $this->algorithm = $x['algorithm'];
            $this->key       = base64_encode(substr($this->rdata, 4));

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if (strlen($this->key) > 0) {
            $data = pack('nCC', $this->flags, $this->protocol, $this->algorithm);
            $data .= base64_decode($this->key);

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
