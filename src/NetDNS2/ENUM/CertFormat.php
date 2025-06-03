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

namespace NetDNS2\ENUM;

enum CertFormat: int
{
    use \NetDNS2\ENUM\Base;

    case PKIX      = 1;
    case SPKI      = 2;
    case PGP       = 3;
    case IPKIX     = 4;
    case ISPKI     = 5;
    case IPGP      = 6;
    case ACPKIX    = 7;
    case IACPKIX   = 8;
    case URI       = 253;
    case OID       = 254;

    public function label(): string
    {
        return match($this)
        {
            self::PKIX      => 'PKIX',
            self::SPKI      => 'SPKI',
            self::PGP       => 'PGP',
            self::IPKIX     => 'IPKIX',
            self::ISPKI     => 'ISPKI',
            self::IPGP      => 'IPGP',
            self::ACPKIX    => 'ACPKIX',
            self::IACPKIX   => 'IACPKIX', 
            self::URI       => 'URI',
            self::OID       => 'OID'
        };
    }
}
