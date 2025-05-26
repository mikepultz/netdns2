<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2025, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   NetDNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2025 Mike Pultz <mike@mikepultz.com>
 * @license   https://opensource.org/license/bsd-3-clause/ BSD-3-Clause
 * @link      https://netdns2.com/
 * @since     1.6.0
 *
 */

namespace NetDNS2\RR;

/**
 *  https://datatracker.ietf.org/doc/draft-ietf-dnsop-generalized-notify/09/
 * 
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | RRtype                        | Scheme        | Port
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                  | Target ...  /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-/
 *
 */
final class DSYNC extends \NetDNS2\RR
{
    /**
     * defined DSYNC schemes
     */
    public const DSYNC_SCHEME_NULL      = 0;
    public const DSYNC_SCHEME_NOTIFY    = 1;
                                                // 128-255 reserved for future use

    /**
     * scheme lookup tables
     *
     * @var array<int,string>
     */
    public static array $scheme_id_to_name = [

        self::DSYNC_SCHEME_NULL     => 'NULL',
        self::DSYNC_SCHEME_NOTIFY   => 'NOTIFY'
    ];

    /**
     * @var array<string,int>
     */
    public static array $scheme_name_to_id = [

        'NULL'      => self::DSYNC_SCHEME_NULL,
        'NOTIFY'    => self::DSYNC_SCHEME_NOTIFY
    ];

    /**
     * RR types supported by DSYNC
     *
     * @var array<int,string>
     */
    public static array $supported_rr_types = [ 'CDS', 'CSYNC' ];    

    /**
     *
     */
    protected string $rrtype;

    /**
     *
     */
    protected string $scheme;

    /**
     *
     */
    protected int $port;

    /**
     *
     */
    protected \NetDNS2\Data\Domain $target;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->rrtype . ' ' . $this->scheme . ' ' . $this->port . ' ' . $this->target . '.';
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        //
        // lookup and store the RR mnemonic
        //
        $rrtype = strtoupper($this->sanitize(array_shift($_rdata)));

        if (in_array($rrtype, self::$supported_rr_types) == true)
        {
            $this->rrtype = $rrtype;
        } else
        {
            throw new \NetDNS2\Exception('unsupported RR type for DSYNC record: ' . $rrtype, \NetDNS2\ENUM\Error::RR_INVALID);
        }

        //
        // lookup and store the scheme mnemonic
        //
        $scheme = strtoupper($this->sanitize(array_shift($_rdata)));

        if (isset(self::$scheme_name_to_id[$scheme]) == true)
        {
            $this->scheme = $scheme;
        } else
        {
            throw new \NetDNS2\Exception('unsupported scheme value for DSYNC record: ' . $scheme, \NetDNS2\ENUM\Error::PARSE_ERROR);
        }

        $this->port   = intval($this->sanitize(array_shift($_rdata)));
        $this->target = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, $this->sanitize(array_shift($_rdata)));

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

        $val = unpack('nx/Cy/nz', $this->rdata);
        if ($val === false)
        {
            return false;
        }            

        list('x' => $rrtype, 'y' => $scheme, 'z' => $this->port) = (array)$val;
        $offset = $_packet->offset + 5;

        //
        // lookup the rrtype value
        //
        $rr = \NetDNS2\ENUM\RRType::set($rrtype);

        if (in_array($rr->label(), self::$supported_rr_types) == true)
        {
            $this->rrtype = $rr->label();
        } else
        {
            throw new \NetDNS2\Exception('unsupported RR type for DSYNC record: ' . $rrtype, \NetDNS2\ENUM\Error::RR_INVALID);
        }

        //
        // lookup the scheme value
        //
        if (isset(self::$scheme_id_to_name[$scheme]) == true)
        {
            $this->scheme = self::$scheme_id_to_name[$scheme];
        } else
        {
            throw new \NetDNS2\Exception('unsupported scheme value for DSYNC record: ' . $scheme, \NetDNS2\ENUM\Error::PARSE_ERROR);
        }

        $this->target = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, $_packet, $offset);

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        $_packet->offset += 5;

        return pack('nCn', \NetDNS2\ENUM\RRType::set($this->rrtype)->value, 
            self::$scheme_name_to_id[$this->scheme], $this->port) . $this->target->encode();
    }
}
