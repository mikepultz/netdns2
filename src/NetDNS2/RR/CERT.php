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
 * @since     0.6.0
 *
 */

namespace NetDNS2\RR;

/**
 * CERT Resource Record - RFC4398 section 2
 *
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |            format             |             key tag           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   algorithm   |                                               /
 *  +---------------+            certificate or CRL                 /
 *  /                                                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
 *
 */
final class CERT extends \NetDNS2\RR
{
    /*
     * format's allowed for certificates
     */
    public const CERT_FORMAT_RES       = 0;
    public const CERT_FORMAT_PKIX      = 1;
    public const CERT_FORMAT_SPKI      = 2;
    public const CERT_FORMAT_PGP       = 3;
    public const CERT_FORMAT_IPKIX     = 4;
    public const CERT_FORMAT_ISPKI     = 5;
    public const CERT_FORMAT_IPGP      = 6;
    public const CERT_FORMAT_ACPKIX    = 7;
    public const CERT_FORMAT_IACPKIX   = 8;
    public const CERT_FORMAT_URI       = 253;
    public const CERT_FORMAT_OID       = 254;

    /**
     * @var array<string,int>
     */
    public array $cert_format_name_to_id = [];

    /**
     * @var array<int,string>
     */
    public array $cert_format_id_to_name = [

        self::CERT_FORMAT_RES       => 'Reserved',
        self::CERT_FORMAT_PKIX      => 'PKIX',
        self::CERT_FORMAT_SPKI      => 'SPKI',
        self::CERT_FORMAT_PGP       => 'PGP',
        self::CERT_FORMAT_IPKIX     => 'IPKIX',
        self::CERT_FORMAT_ISPKI     => 'ISPKI',
        self::CERT_FORMAT_IPGP      => 'IPGP',
        self::CERT_FORMAT_ACPKIX    => 'ACPKIX',
        self::CERT_FORMAT_IACPKIX   => 'IACPKIX',
        self::CERT_FORMAT_URI       => 'URI',
        self::CERT_FORMAT_OID       => 'OID'
    ];

    /**
     * certificate format
     */
    protected int $format;

    /**
     * key tag
     */
    protected int $keytag;

    /**
     * The algorithm used for the cert
     */
    protected \NetDNS2\ENUM\DNSSEC\Algorithm $algorithm;

    /**
     * certificate
     */
    protected string $certificate = '';

    /**
     * we have our own constructor so that we can load our certificate
     * information for parsing.
     *
     * @param \NetDNS2\Packet     &$_packet a \NetDNS2\Packet packet to parse the RR from
     * @param array<string,mixed> $_rr      a array with parsed RR values
     *
     */
    public function __construct(?\NetDNS2\Packet &$_packet = null, ?array $_rr = null)
    {
        parent::__construct($_packet, $_rr);
    
        //
        // load the lookup values
        //
        $this->cert_format_name_to_id = array_flip($this->cert_format_id_to_name);
    }

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->format . ' ' . $this->keytag . ' ' . $this->algorithm->value . ' ' . base64_encode($this->certificate);
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $format             = $this->sanitize(array_shift($_rdata));
        $this->keytag       = intval($this->sanitize(array_shift($_rdata)));
        $this->algorithm    = \NetDNS2\ENUM\DNSSEC\Algorithm::set($this->sanitize(array_shift($_rdata)));

        //
        // check the format; can be an int, or a mnemonic symbol
        //
        if (is_numeric($format) == false)
        {
            $mnemonic = strtoupper(trim($format));

            if (isset($this->cert_format_name_to_id[$mnemonic]) == false)
            {
                throw new \NetDNS2\Exception('invalid format value provided: ' . $format, \NetDNS2\ENUM\Error::PARSE_ERROR);
            }

            $this->format = $this->cert_format_name_to_id[$mnemonic];

        } else
        {
            if (isset($this->cert_format_id_to_name[$format]) == false)
            {
                throw new \NetDNS2\Exception('invalid format value provided: ' . $format, \NetDNS2\ENUM\Error::PARSE_ERROR);
            }

            $this->format = intval($format);
        }
    
        //
        // parse and base64 decode the certificate
        //
        // certificates MUST be provided base64 encoded, if not, everything will be broken after this point, as we assume it's base64 encoded.
        //
        $this->certificate = base64_decode(implode(' ', $_rdata));

        if ($this->certificate === false)
        {
            throw new \NetDNS2\Exception('invalid certificate value provided: ' . $this->certificate, \NetDNS2\ENUM\Error::PARSE_ERROR);
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
        // unpack the format, keytag and algorithm
        //
        $val = unpack('nx/ny/Cz', $this->rdata);
        if ($val === false)
        {
            return false;
        }

        list('x' => $this->format, 'y' => $this->keytag, 'z' => $algorithm) = (array)$val;

        $this->algorithm = \NetDNS2\ENUM\DNSSEC\Algorithm::set($algorithm);

        //
        // copy the certificate
        //
        $this->certificate = substr($this->rdata, 5, $this->rdlength - 5);

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
        
        $_packet->offset += strlen($this->certificate) + 5;

        return pack('nnC', $this->format, $this->keytag, $this->algorithm->value) . $this->certificate;
    }
}
