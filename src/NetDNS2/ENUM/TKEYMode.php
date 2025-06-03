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

enum TKEYMode: int
{
    use \NetDNS2\ENUM\Base;

    case RES           = 0;
    case SERV_ASSIGN   = 1;
    case DH            = 2;
    case GSS_API       = 3;
    case RESV_ASSIGN   = 4;
    case KEY_DELE      = 5;

    public function label(): string
    {
        return match($this)
        {
            self::RES           => 'Reserved',
            self::SERV_ASSIGN   => 'Server Assignment',
            self::DH            => 'Diffie-Hellman',
            self::GSS_API       => 'GSS-API',
            self::RESV_ASSIGN   => 'Resolver Assignment',
            self::KEY_DELE      => 'Key Deletion'
        };
    }
}
