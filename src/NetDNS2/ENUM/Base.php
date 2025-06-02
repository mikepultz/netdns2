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

trait Base
{
    public static function set(string|int $_id): self
    {
        foreach(self::cases() as $entry)
        {
            if (((is_numeric($_id) == true) ? $entry->value : $entry->label()) == $_id)
            {
                return $entry;
            }
        }

        throw new \NetDNS2\Exception(sprintf('invalid enum value %s specified.', $_id), \NetDNS2\ENUM\Error::INT_INVALID_ENUM);
    }
    public static function exists(string|int $_id): bool
    {
        try 
        {
            $res = self::set($_id);
            return true;

        } catch(\NetDNS2\Exception)
        {
            return false;
        }
    }
}
