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
 * @since     1.2.5
 *
 */

namespace NetDNS2\RR;

/**
 * TLSA Resource Record - RFC 6698
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Cert. Usage  |   Selector    | Matching Type |               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               /
 *  /                                                               /
 *  /                 Certificate Association Data                  /
 *  /                                                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
class TLSA extends \NetDNS2\RR
{
    /**
     * The Certificate Usage Field
     */
    protected int $cert_usage;

    /**
     * The Selector Field
     */
    protected int $selector;

    /**
     * The Matching Type Field
     */
    protected int $matching_type;

    /**
     * The Certificate Association Data Field
     */
    protected string $certificate;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->cert_usage . ' ' . $this->selector . ' ' . $this->matching_type . ' ' . $this->certificate;
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->cert_usage    = intval($this->sanitize(array_shift($_rdata)));
        $this->selector      = intval($this->sanitize(array_shift($_rdata)));
        $this->matching_type = intval($this->sanitize(array_shift($_rdata)));
        $this->certificate   = implode('', $_rdata);

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
        // unpack the format, keytag and algorithm
        //
        $val = unpack('Cx/Cy/Cz', $this->rdata);
        if ($val === false)
        {
            return false;
        }

        list('x' => $this->cert_usage, 'y' => $this->selector, 'z' => $this->matching_type) = (array)$val;

        //
        // copy the certificate
        //
        $val = unpack('H*', substr($this->rdata, 3, $this->rdlength - 3));
        if ($val === false)
        {
            return false;
        }

        $this->certificate  = implode('', (array)$val);

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if (strlen($this->certificate) == 0)
        {
            return '';
        }

        $cert = pack('H*', $this->certificate);

        $_packet->offset = strlen($cert) + 3;
            
        return pack('CCC', $this->cert_usage, $this->selector, $this->matching_type) . $cert;
    }
}
