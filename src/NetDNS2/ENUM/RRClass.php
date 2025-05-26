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

enum RRClass: int
{
    use \NetDNS2\ENUM\Base;

    case IN    = 1;    // RFC 1035
    case CH    = 3;    // RFC 1035
    case HS    = 4;    // RFC 1035
    case NONE  = 254;  // RFC 2136
    case ANY   = 255;  // RFC 1035

    public function label(): string
    {
        return match($this)
        {
            self::IN    => 'IN',
            self::CH    => 'CH',
            self::HS    => 'HS',
            self::NONE  => 'NONE',
            self::ANY   => 'ANY'
        };
    }
}
