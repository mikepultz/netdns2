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
 * WKS Resource Record - RFC1035 section 3.4.2
 *
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    ADDRESS                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |       PROTOCOL        |                       |
 *   +--+--+--+--+--+--+--+--+                       |
 *   |                                               |
 *   /                   <BIT MAP>                   /
 *   /                                               /
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class Net_DNS2_RR_WKS extends Net_DNS2_RR
{
    public string $address = '';
    public int $protocol = 0;
    /** @var array<int, int> */
    public array $bitmap = [];

    #[\Override]
    protected function rrToString(): string
    {
        $data = $this->address . ' ' . $this->protocol;

        foreach ($this->bitmap as $port) {
            $data .= ' ' . $port;
        }

        return $data;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->address  = strtolower(trim(array_shift($rdata), '.'));
        $this->protocol = (int)array_shift($rdata);
        $this->bitmap   = $rdata;

        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $x = unpack('Naddress/Cprotocol', $this->rdata);

            $this->address  = long2ip($x['address']);
            $this->protocol = $x['protocol'];

            $port = 0;
            foreach (unpack('@5/C*', $this->rdata) as $set) {

                $s = sprintf('%08b', $set);

                for ($i = 0; $i < 8; $i++, $port++) {
                    if ($s[$i] === '1') {
                        $this->bitmap[] = $port;
                    }
                }
            }

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if (strlen($this->address) > 0) {

            $data = pack('NC', ip2long($this->address), $this->protocol);

            $ports = [];

            $n = 0;
            foreach ($this->bitmap as $port) {
                $ports[$port] = 1;

                if ($port > $n) {
                    $n = $port;
                }
            }
            for ($i = 0; $i < ceil($n / 8) * 8; $i++) {
                if (!isset($ports[$i])) {
                    $ports[$i] = 0;
                }
            }

            ksort($ports);

            $string = '';
            $n = 0;

            foreach ($ports as $s) {

                $string .= $s;
                $n++;

                if ($n === 8) {
                    $data .= chr(bindec($string));
                    $string = '';
                    $n = 0;
                }
            }

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
