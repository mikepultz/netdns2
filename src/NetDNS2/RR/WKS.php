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
 * @since     1.0.1
 *
 */

namespace NetDNS2\RR;

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
 *
 */
final class WKS extends \NetDNS2\RR
{
    /**
     * The IP address of the service
     */
    protected string $address;

    /**
     * The protocol of the service
     */
    protected int $protocol;

    /**
     * bitmap
     *
     * @var array<int,int>
     */
    protected array $bitmap = [];

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->address . ' ' . $this->protocol . ' ' . implode(' ', $this->bitmap);
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->address  = $this->sanitize(array_shift($_rdata));
        $this->protocol = intval($this->sanitize(array_shift($_rdata)));

        foreach($_rdata as $value)
        {
            $this->bitmap[] = intval($value);
        }

        if (\NetDNS2\Client::isIPv4($this->address) == false)
        {
            throw new \NetDNS2\Exception('address value provided is not a valid IPv4 address: ' . $this->address, \NetDNS2\ENUM\Error::PARSE_ERROR);
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
            
        //
        // get the address and protocol value
        //
        $val = unpack('Nx/Cy', $this->rdata);
        if ($val === false)
        {
            return false;
        }

        list('x' => $address, 'y' => $this->protocol) = (array)$val;

        //
        // convert the IP
        //
        $this->address = long2ip(intval($address));

        //
        // unpack the port list bitmap
        //
        $port = 0;

        $val = unpack('@5/C*', $this->rdata);
        if ($val === false)
        {
            return false;
        }

        foreach((array)$val as $set)
        {
            $s = sprintf('%08b', $set);

            for($i=0; $i<8; $i++, $port++)
            {
                if ($s[$i] == '1')
                {
                    $this->bitmap[] = $port;
                }
            }
        }

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if (strlen($this->address) == 0)
        {
            return '';
        }
            
        $data = pack('NC', ip2long($this->address), $this->protocol);

        $ports = [];
        $n = 0;

        foreach($this->bitmap as $port)
        {
            $ports[$port] = 1;

            if ($port > $n)
            {
                $n = $port;
            }
        }
        for($i=0; $i<ceil($n/8)*8; $i++)
        {
            if (!isset($ports[$i]))
            {
                $ports[$i] = 0;
            }
        }

        ksort($ports);

        $string = '';
        $n = 0;

        foreach($ports as $s)
        {
            $string .= $s;
            $n++;

            if ($n == 8)
            {
                $data .= chr(intval(bindec($string)));
                $string = '';
                $n = 0;
            }
        }

        $_packet->offset += strlen($data);

        return $data;
    }
}
