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

/**
 * DNS Question section - RFC1035 section 4.1.2
 */
class Net_DNS2_Question
{
    public string $qname;
    public string $qtype;
    public string $qclass;

    /**
     * @throws Net_DNS2_Exception
     */
    public function __construct(?Net_DNS2_Packet &$packet = null)
    {
        if ($packet !== null) {
            $this->set($packet);
        } else {
            $this->qname  = '';
            $this->qtype  = 'A';
            $this->qclass = 'IN';
        }
    }

    public function __toString(): string
    {
        return ";;\n;; Question:\n;;\t {$this->qname}. {$this->qtype} {$this->qclass}\n";
    }

    /**
     * @throws Net_DNS2_Exception
     */
    public function set(Net_DNS2_Packet &$packet): bool
    {
        $this->qname = $packet->expand($packet, $packet->offset);
        if ($packet->rdlength < ($packet->offset + 4)) {
            throw new Net_DNS2_Exception(
                'invalid question section: too small',
                Net_DNS2_Lookups::E_QUESTION_INVALID
            );
        }

        $type  = ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);
        $class = ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);

        $type_name  = Net_DNS2_Lookups::$rr_types_by_id[$type] ?? null;
        $class_name = Net_DNS2_Lookups::$classes_by_id[$class] ?? null;

        if ($type_name === null || $class_name === null) {
            throw new Net_DNS2_Exception(
                "invalid question section: invalid type ({$type}) or class ({$class}) specified.",
                Net_DNS2_Lookups::E_QUESTION_INVALID
            );
        }

        $this->qtype  = $type_name;
        $this->qclass = $class_name;

        return true;
    }

    /**
     * @throws Net_DNS2_Exception
     */
    public function get(Net_DNS2_Packet &$packet): string
    {
        $type  = Net_DNS2_Lookups::$rr_types_by_name[$this->qtype] ?? null;
        $class = Net_DNS2_Lookups::$classes_by_name[$this->qclass] ?? null;

        if ($type === null || $class === null) {
            throw new Net_DNS2_Exception(
                "invalid question section: invalid type ({$this->qtype}) or class ({$this->qclass}) specified.",
                Net_DNS2_Lookups::E_QUESTION_INVALID
            );
        }

        $data = $packet->compress($this->qname, $packet->offset);
        $data .= chr($type >> 8) . chr($type) . chr($class >> 8) . chr($class);
        $packet->offset += 4;

        return $data;
    }
}
