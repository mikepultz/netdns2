<?php declare(strict_types=1);

namespace Net\DNS2\Packet;

use Net\DNS2\DNS2;
use Net\DNS2\Lookups;
use Net\DNS2\Exception;
use Net\DNS2\Header;
use Net\DNS2\Question;

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 */

class Request extends Packet
{
    /**
     * @throws Exception
     */
    public function __construct(string $name, ?string $type = null, ?string $class = null)
    {
        $this->set($name, $type, $class);
    }

    /**
     * @throws Exception
     */
    public function set(string $name, ?string $type = 'A', ?string $class = 'IN'): bool
    {
        $this->header = new Header();

        $q = new Question();

        if ($name !== '.') {
            $name = trim(strtolower($name), " \t\n\r\0\x0B.");
        }

        $type  = strtoupper(trim((string)$type));
        $class = strtoupper(trim((string)$class));

        if ($name === '') {
            throw new Exception(
                'empty query string provided',
                Lookups::E_PACKET_INVALID
            );
        }

        if ($type === '*') {
            $type = 'ANY';
        }

        if (!isset(Lookups::$rr_types_by_name[$type])
            || !isset(Lookups::$classes_by_name[$class])
        ) {
            throw new Exception(
                "invalid type ({$type}) or class ({$class}) specified.",
                Lookups::E_PACKET_INVALID
            );
        }

        if ($type === 'PTR') {
            if (DNS2::isIPv4($name)) {
                $name = implode('.', array_reverse(explode('.', $name))) . '.in-addr.arpa';
            } elseif (DNS2::isIPv6($name)) {
                $e = DNS2::expandIPv6($name);
                if ($e !== false) {
                    $name = implode('.', array_reverse(str_split(str_replace(':', '', $e)))) . '.ip6.arpa';
                } else {
                    throw new Exception(
                        "unsupported PTR value: {$name}",
                        Lookups::E_PACKET_INVALID
                    );
                }
            }
        }

        $q->qname  = $name;
        $q->qtype  = $type;
        $q->qclass = $class;

        $this->question   = [$q];
        $this->answer     = [];
        $this->authority  = [];
        $this->additional = [];

        return true;
    }
}
