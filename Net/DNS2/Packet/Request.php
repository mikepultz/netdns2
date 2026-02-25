<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   Net_DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 */

class Net_DNS2_Packet_Request extends Net_DNS2_Packet
{
    /**
     * @throws Net_DNS2_Exception
     */
    public function __construct(string $name, ?string $type = null, ?string $class = null)
    {
        $this->set($name, $type, $class);
    }

    /**
     * @throws Net_DNS2_Exception
     */
    public function set(string $name, ?string $type = 'A', ?string $class = 'IN'): bool
    {
        $this->header = new Net_DNS2_Header();

        $q = new Net_DNS2_Question();

        if ($name !== '.') {
            $name = trim(strtolower($name), " \t\n\r\0\x0B.");
        }

        $type  = strtoupper(trim((string)$type));
        $class = strtoupper(trim((string)$class));

        if ($name === '') {
            throw new Net_DNS2_Exception(
                'empty query string provided',
                Net_DNS2_Lookups::E_PACKET_INVALID
            );
        }

        if ($type === '*') {
            $type = 'ANY';
        }

        if (!isset(Net_DNS2_Lookups::$rr_types_by_name[$type])
            || !isset(Net_DNS2_Lookups::$classes_by_name[$class])
        ) {
            throw new Net_DNS2_Exception(
                "invalid type ({$type}) or class ({$class}) specified.",
                Net_DNS2_Lookups::E_PACKET_INVALID
            );
        }

        if ($type === 'PTR') {
            if (Net_DNS2::isIPv4($name)) {
                $name = implode('.', array_reverse(explode('.', $name))) . '.in-addr.arpa';
            } elseif (Net_DNS2::isIPv6($name)) {
                $e = Net_DNS2::expandIPv6($name);
                if ($e !== false) {
                    $name = implode('.', array_reverse(str_split(str_replace(':', '', $e)))) . '.ip6.arpa';
                } else {
                    throw new Net_DNS2_Exception(
                        "unsupported PTR value: {$name}",
                        Net_DNS2_Lookups::E_PACKET_INVALID
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
