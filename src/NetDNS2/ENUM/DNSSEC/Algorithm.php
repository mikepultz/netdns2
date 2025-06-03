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
 * @copyright 2025 Mike Pultz <mike@mikepultz.com>
 * @license   https://opensource.org/license/bsd-3-clause/ BSD-3-Clause
 * @link      https://netdns2.com/
 * @since     2.0.0
 *
 */

namespace NetDNS2\ENUM\DNSSEC;

enum Algorithm: int
{
    use \NetDNS2\ENUM\Base;

    case RES                = 0;    // Reserved
    case RSAMD5             = 1;    // RFC 2538 - Not Recommended
    case DH                 = 2;    // RFC 2539
    case DSA                = 3;    // RFC 2536 - Optional
    case ECC                = 4;    // TBA
    case RSASHA1            = 5;    // RFC3110  - Mandatory
    case DSANSEC3SHA1       = 6;
    case RSASHA1NSEC3SHA1   = 7;
    case RSASHA256          = 8;
    case RSASHA512          = 10;
    case ECCGOST            = 12;
    case ECDSAP256SHA256    = 13;
    case ECDSAP384SHA384    = 14;
    case ED25519            = 15;
    case ED448              = 16;
    case SM2SM3             = 17;
    case ECCGOST12          = 23;
    case INDIRECT           = 252;
    case PRIVATEDNS         = 253;
    case PRIVATEOID         = 254;

    public function label(): string
    {
        return match($this)
        {
            self::RES               => 'RES',
            self::RSAMD5            => 'RSAMD5',
            self::DH                => 'DH',
            self::DSA               => 'DSA',
            self::ECC               => 'ECC',
            self::RSASHA1           => 'RSASHA1',
            self::DSANSEC3SHA1      => 'DSA-NSEC3-SHA1',
            self::RSASHA1NSEC3SHA1  => 'RSASHA1-NSEC3-SHA1',
            self::RSASHA256         => 'RSASHA256',
            self::RSASHA512         => 'RSASHA512',
            self::ECCGOST           => 'ECC-GOST',
            self::ECDSAP256SHA256   => 'ECDSAP256SHA256',
            self::ECDSAP384SHA384   => 'ECDSAP384SHA384',
            self::ED25519           => 'ED25519',
            self::ED448             => 'ED448',
            self::SM2SM3            => 'SM2SM3',
            self::ECCGOST12         => 'ECC-GOST12',
            self::INDIRECT          => 'INDIRECT',
            self::PRIVATEDNS        => 'PRIVATEDNS',
            self::PRIVATEOID        => 'PRIVATEOID',
        };
    }

    //
    // return a matching OpenSSL algo
    //
    public function openssl(): int
    {
        return match($this)
        {
            self::RSAMD5        => OPENSSL_ALGO_MD5,
            self::RSASHA1       => OPENSSL_ALGO_SHA1,
            self::RSASHA256     => OPENSSL_ALGO_SHA256,
            self::RSASHA512     => OPENSSL_ALGO_SHA512,
            default             => throw new \NetDNS2\Exception(sprintf('algorithm %s does not currently have openssl support.', $this->label()), \NetDNS2\ENUM\Error::INT_INVALID_ALGORITHM)
        };
    }
}
