<?php declare(strict_types=1);

namespace Net\DNS2;

use Net\DNS2\Packet\Packet;

/**
 * DNS Question section - RFC1035 section 4.1.2
 */
class Question
{
    public string $qname;
    public string $qtype;
    public string $qclass;

    /**
     * @throws Exception
     */
    public function __construct(?Packet &$packet = null)
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
     * @throws Exception
     */
    public function set(Packet &$packet): bool
    {
        $this->qname = $packet->expand($packet, $packet->offset);
        if ($packet->rdlength < ($packet->offset + 4)) {
            throw new Exception(
                'invalid question section: too small',
                Lookups::E_QUESTION_INVALID
            );
        }

        $type  = ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);
        $class = ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);

        $type_name  = Lookups::$rr_types_by_id[$type] ?? null;
        $class_name = Lookups::$classes_by_id[$class] ?? null;

        if ($type_name === null || $class_name === null) {
            throw new Exception(
                "invalid question section: invalid type ({$type}) or class ({$class}) specified.",
                Lookups::E_QUESTION_INVALID
            );
        }

        $this->qtype  = $type_name;
        $this->qclass = $class_name;

        return true;
    }

    /**
     * @throws Exception
     */
    public function get(Packet &$packet): string
    {
        $type  = Lookups::$rr_types_by_name[$this->qtype] ?? null;
        $class = Lookups::$classes_by_name[$this->qclass] ?? null;

        if ($type === null || $class === null) {
            throw new Exception(
                "invalid question section: invalid type ({$this->qtype}) or class ({$this->qclass}) specified.",
                Lookups::E_QUESTION_INVALID
            );
        }

        $data = $packet->compress($this->qname, $packet->offset);
        $data .= chr($type >> 8) . chr($type) . chr($class >> 8) . chr($class);
        $packet->offset += 4;

        return $data;
    }
}
