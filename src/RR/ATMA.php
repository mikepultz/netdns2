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
 * ATMA Resource Record
 */
class ATMA extends RR
{
    public int $format = 0;
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

        if (ctype_xdigit($value) === true) {
            $this->format   = 0;
            $this->address  = $value;
        } elseif (is_numeric($value) === true) {
            $this->format   = 1;
            $this->address  = $value;
        } else {
            return false;
        }

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('Cformat/N*address', $this->rdata);

            $this->format = $x['format'];

            if ($this->format === 0) {
                $a = unpack('@1/H*address', $this->rdata);
                $this->address = $a['address'];
            } elseif ($this->format === 1) {
                $this->address = substr($this->rdata, 1, $this->rdlength - 1);
            } else {
                return false;
            }

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        $data = chr($this->format);

        if ($this->format === 0) {
            $data .= pack('H*', $this->address);
        } elseif ($this->format === 1) {
            $data .= $this->address;
        } else {
            return null;
        }

        $packet->offset += strlen($data);

        return $data;
    }
}
