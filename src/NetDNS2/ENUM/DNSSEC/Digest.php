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

enum Digest: int
{
    use \NetDNS2\ENUM\Base;

    case SHA1               = 0;    // RFC 3658
    case SHA256             = 2;    // RFC 3658
    case ECCGOST            = 3;    // RFC 5933 - Deprecated
    case SHA384             = 4;    // RFC 6605
    case ECCGOST12          = 5;    // RFC 9558
    case SM2SM3             = 6;    // RFC 9563

    public function label(): string
    {
        return match($this)
        {
            self::SHA1      => 'SHA-1',
            self::SHA256    => 'SHA-256',
            self::ECCGOST   => 'ECC-GOST',
            self::SHA384    => 'SHA-384',
            self::ECCGOST12 => 'ECC-GOST12',
            self::SM2SM3    => 'SM2'
        };
    }
}
