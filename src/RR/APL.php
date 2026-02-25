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
 * APL Resource Record - RFC3123
 */
class APL extends RR
{
    /** @var array<int, array<string, mixed>> */
    public array $apl_items = [];

    #[\Override]
    protected function rrToString(): string
    {
        $out = '';

        foreach ($this->apl_items as $item) {
            if ($item['n'] === 1) {
                $out .= '!';
            }

            $out .= $item['address_family'] . ':' .
                $item['afd_part'] . '/' . $item['prefix'] . ' ';
        }

        return trim($out);
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        foreach ($rdata as $item) {
            if (preg_match('/^(!?)([1|2])\:([^\/]*)\/([0-9]{1,3})$/', $item, $m)) {
                $i = [
                    'address_family'    => $m[2],
                    'prefix'            => $m[4],
                    'n'                 => ($m[1] === '!') ? 1 : 0,
                    'afd_part'          => strtolower($m[3])
                ];

                $address = $this->_trimZeros(
                    $i['address_family'], $i['afd_part']
                );

                $i['afd_length'] = count(explode('.', $address));

                $this->apl_items[] = $i;
            }
        }

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $offset = 0;

            while ($offset < $this->rdlength) {
                $x = unpack(
                    'naddress_family/Cprefix/Cextra', substr($this->rdata, $offset)
                );

                $item = [
                    'address_family'    => $x['address_family'],
                    'prefix'            => $x['prefix'],
                    'n'                 => ($x['extra'] >> 7) & 0x1,
                    'afd_length'        => $x['extra'] & 0xf
                ];

                switch ($item['address_family']) {
                    case 1:
                        $r = unpack(
                            'C*', substr($this->rdata, $offset + 4, $item['afd_length'])
                        );
                        if (count($r) < 4) {
                            for ($c = count($r) + 1; $c < 4 + 1; $c++) {
                                $r[$c] = 0;
                            }
                        }

                        $item['afd_part'] = implode('.', $r);
                        break;

                    case 2:
                        $r = unpack(
                            'C*', substr($this->rdata, $offset + 4, $item['afd_length'])
                        );
                        if (count($r) < 8) {
                            for ($c = count($r) + 1; $c < 8 + 1; $c++) {
                                $r[$c] = 0;
                            }
                        }

                        $item['afd_part'] = sprintf(
                            '%x:%x:%x:%x:%x:%x:%x:%x',
                            $r[1], $r[2], $r[3], $r[4], $r[5], $r[6], $r[7], $r[8]
                        );
                        break;

                    default:
                        return false;
                }

                $this->apl_items[] = $item;

                $offset += 4 + $item['afd_length'];
            }

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (count($this->apl_items) > 0) {
            $data = '';

            foreach ($this->apl_items as $item) {
                $data .= pack(
                    'nCC',
                    $item['address_family'],
                    $item['prefix'],
                    ($item['n'] << 7) | $item['afd_length']
                );

                switch ($item['address_family']) {
                    case 1:
                        $address = explode(
                            '.',
                            $this->_trimZeros($item['address_family'], $item['afd_part'])
                        );

                        foreach ($address as $b) {
                            $data .= chr((int)$b);
                        }
                        break;

                    case 2:
                        $address = explode(
                            ':',
                            $this->_trimZeros($item['address_family'], $item['afd_part'])
                        );

                        foreach ($address as $b) {
                            $data .= pack('H', $b);
                        }
                        break;

                    default:
                        return null;
                }
            }

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }

    private function _trimZeros(int|string $family, string $address): string
    {
        $a = [];

        switch ($family) {
            case 1:
                $a = array_reverse(explode('.', $address));
                break;
            case 2:
                $a = array_reverse(explode(':', $address));
                break;
            default:
                return '';
        }

        foreach ($a as $value) {
            if ($value === '0') {
                array_shift($a);
            }
        }

        $out = '';

        switch ($family) {
            case 1:
                $out = implode('.', array_reverse($a));
                break;
            case 2:
                $out = implode(':', array_reverse($a));
                break;
            default:
                return '';
        }

        return $out;
    }
}
