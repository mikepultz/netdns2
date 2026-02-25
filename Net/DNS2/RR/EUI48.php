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
 * EUI48 Resource Record - RFC7043 section 3.1
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          EUI-48 Address                       |
 * |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class Net_DNS2_RR_EUI48 extends Net_DNS2_RR
{
    public string $address = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->address;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $value = array_shift($rdata);

        $a = explode('-', $value);
        if (count($a) !== 6) {
            return false;
        }

        foreach ($a as $i) {
            if (ctype_xdigit($i) === false) {
                return false;
            }
        }

        $this->address = strtolower($value);

        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('C6', $this->rdata);
            if (count($x) === 6) {
                $this->address = vsprintf('%02x-%02x-%02x-%02x-%02x-%02x', $x);
                return true;
            }
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        $data = '';

        $a = explode('-', $this->address);
        foreach ($a as $b) {
            $data .= chr(hexdec($b));
        }

        $packet->offset += 6;
        return $data;
    }
}
