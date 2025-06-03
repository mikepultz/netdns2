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

enum OpCode: int
{
    use \NetDNS2\ENUM\Base;

    case QUERY          = 0;     // RFC 1035
    case IQUERY         = 1;     // RFC 1035, RFC 3425
    case STATUS         = 2;     // RFC 1035
    case NOTIFY         = 4;     // RFC 1996
    case UPDATE         = 5;     // RFC 2136
    case DSO            = 6;     // RFC 8490

    public function label(): string
    {
        return match($this)
        {
            self::QUERY     => 'Query',
            self::IQUERY    => 'IQuery',
            self::STATUS    => 'Status',
            self::NOTIFY    => 'Notify',
            self::UPDATE    => 'Update',
            self::DSO       => 'DSO'
        };
    }
}
