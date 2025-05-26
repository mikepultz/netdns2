<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2023, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   NetDNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2023 Mike Pultz <mike@mikepultz.com>
 * @license   https://opensource.org/license/bsd-3-clause/ BSD-3-Clause
 * @link      https://netdns2.com/
 * @since     1.0.0
 *
 */

namespace NetDNS2\RR;

/**
 * APL Resource Record - RFC3123
 *
 *     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *     |                          ADDRESSFAMILY                        |
 *     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *     |             PREFIX            | N |         AFDLENGTH         |
 *     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *     /                            AFDPART                            /
 *     |                                                               |
 *     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *
 */
final class APL extends \NetDNS2\RR
{
    /**
     * a list of all the address prefix list items
     *
     * @var array<int,mixed>
     */
    protected array $apl_items = [];

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        $out = '';

        foreach($this->apl_items as $item)
        {
            if ($item['n'] == 1)
            {
                $out .= '!';
            }

            $out .= $item['address_family'] . ':' . $item['afd_part'] . '/' . $item['prefix'] . ' ';
        }

        return trim($out);
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        foreach($_rdata as $item)
        {
            if (preg_match('/^(!?)([1|2])\:([^\/]*)\/([0-9]{1,3})$/', $item, $m) == 1)
            {
                $i = [

                    'address_family'    => $m[2],
                    'prefix'            => $m[4],
                    'n'                 => ($m[1] == '!') ? 1 : 0,
                    'afd_part'          => strtolower($m[3])
                ];

                $address = $this->trimZeros(intval($i['address_family']), $i['afd_part']);

                $i['afd_length'] = count(explode('.', $address));

                $this->apl_items[] = $i;
            }
        }

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrSet()
     */
    protected function rrSet(\NetDNS2\Packet &$_packet): bool
    {
        if ($this->rdlength == 0)
        {
            return false;
        }
            
        $offset = 0;

        while($offset < $this->rdlength)
        {
            //
            // unpack the family, prefix, negate and length values
            //
            $val = unpack('naddress_family/Cprefix/Cextra', substr($this->rdata, $offset));
            if ($val === false)
            {
                return false;
            }

            $x = unpack('naddress_family/Cprefix/Cextra', substr($this->rdata, $offset));
            if ($x === false)
            {
                return false;
            }

            $item = [
            
                'address_family'    => $x['address_family'],
                'prefix'            => $x['prefix'],
                'n'                 => ($x['extra'] >> 7) & 0x1,
                'afd_length'        => $x['extra'] & 0xf
            ];

            switch($item['address_family'])
            {
                case 1:
                {
                    $r = unpack('C*', substr($this->rdata, $offset + 4, $item['afd_length']));
                    if ($r === false)
                    {
                        return false;
                    }
                    if (count($r) < 4)
                    {
                        for($c=count($r)+1; $c<4+1; $c++)
                        {
                            $r[$c] = 0;
                        }
                    }

                    $item['afd_part'] = implode('.', $r);
                }
                break;
                case 2:
                {
                    $r = unpack('C*', substr($this->rdata, $offset + 4, $item['afd_length']));
                    if ($r === false)
                    {
                        return false;
                    }

                    if (count($r) < 8)
                    {
                        for($c=count($r)+1; $c<8+1; $c++)
                        {
                            $r[$c] = 0;
                        }
                    }

                    $item['afd_part'] = sprintf('%x:%x:%x:%x:%x:%x:%x:%x', $r[1], $r[2], $r[3], $r[4], $r[5], $r[6], $r[7], $r[8]);
                }
                break;
                default:
                {
                    return false;
                }
            }

            $this->apl_items[] = $item;

            $offset += 4 + $item['afd_length'];
        }

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if (count($this->apl_items) == 0)
        {
            return '';
        }

        $data = '';

        foreach($this->apl_items as $item)
        {
            //
            // pack the address_family and prefix values
            //
            $data .= pack('nCC', $item['address_family'], $item['prefix'], ($item['n'] << 7) | $item['afd_length']);

            switch($item['address_family'])
            {
                case 1:
                {
                    $address = explode('.', $this->trimZeros(intval($item['address_family']), $item['afd_part']));

                    foreach($address as $b)
                    {
                        $data .= chr(intval($b));
                    }
                }
                break;
                case 2:
                {
                    $address = explode(':', $this->trimZeros(intval($item['address_family']), $item['afd_part']));

                    foreach($address as $b)
                    {
                        $data .= pack('H', $b);
                    }
                }
                break;
                default:
                {
                    return '';
                }
            }
        }

        $_packet->offset += strlen($data);

        return $data;
    }

    /**
     * returns an IP address with the right-hand zero's trimmed
     *
     * @param integer $_family  the IP address family from the rdata
     * @param string  $_address the IP address
     *
     * @return string the trimmed IP addresss.
     *
     */
    private function trimZeros(int $_family, string $_address): string
    {
        $a = [];

        switch($_family)
        {
            case 1:
            {
                $a = array_reverse(explode('.', $_address));
            }
            break;
            case 2:
            {
                $a = array_reverse(explode(':', $_address));
            }
            break;
            default:
            {
                return '';
            }
        }

        foreach($a as $value)
        {
            if ($value === '0')
            {
                array_shift($a);
            }
        }

        $out = '';

        switch($_family)
        {
            case 1:
            {
                $out = implode('.', array_reverse($a));
            }
            break;
            case 2:
            {
                $out = implode(':', array_reverse($a));
            }
            break;
            default:
            {
                return '';
            }
        }

        return $out;
    }
}
