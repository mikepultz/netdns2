<?php declare(strict_types=1);

namespace Net\DNS2;

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   \Net\DNS2\DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 */

/**
 * DNS Packet Header - RFC1035 section 4.1.1, RFC4035 section 3.2
 */
class Header
{
    public int $id;
    public int $qr;
    public int $opcode;
    public int $aa;
    public int $tc;
    public int $rd;
    public int $ra;
    public int $z;
    public int $ad;
    public int $cd;
    public int $rcode;
    public int $qdcount;
    public int $ancount;
    public int $nscount;
    public int $arcount;

    /**
     * @throws \Net\DNS2\Exception
     */
    public function __construct(?\Net\DNS2\Packet\Packet &$packet = null)
    {
        if ($packet !== null) {
            $this->set($packet);
        } else {
            $this->id      = $this->nextPacketId();
            $this->qr      = \Net\DNS2\Lookups::QR_QUERY;
            $this->opcode  = \Net\DNS2\Lookups::OPCODE_QUERY;
            $this->aa      = 0;
            $this->tc      = 0;
            $this->rd      = 1;
            $this->ra      = 0;
            $this->z       = 0;
            $this->ad      = 0;
            $this->cd      = 0;
            $this->rcode   = \Net\DNS2\Lookups::RCODE_NOERROR;
            $this->qdcount = 1;
            $this->ancount = 0;
            $this->nscount = 0;
            $this->arcount = 0;
        }
    }

    public function nextPacketId(): int
    {
        if (++\Net\DNS2\Lookups::$next_packet_id > 65535) {
            \Net\DNS2\Lookups::$next_packet_id = 1;
        }

        return \Net\DNS2\Lookups::$next_packet_id;
    }

    public function __toString(): string
    {
        $output = ";;\n;; Header:\n";

        $output .= ";;\t id         = {$this->id}\n";
        $output .= ";;\t qr         = {$this->qr}\n";
        $output .= ";;\t opcode     = {$this->opcode}\n";
        $output .= ";;\t aa         = {$this->aa}\n";
        $output .= ";;\t tc         = {$this->tc}\n";
        $output .= ";;\t rd         = {$this->rd}\n";
        $output .= ";;\t ra         = {$this->ra}\n";
        $output .= ";;\t z          = {$this->z}\n";
        $output .= ";;\t ad         = {$this->ad}\n";
        $output .= ";;\t cd         = {$this->cd}\n";
        $output .= ";;\t rcode      = {$this->rcode}\n";
        $output .= ";;\t qdcount    = {$this->qdcount}\n";
        $output .= ";;\t ancount    = {$this->ancount}\n";
        $output .= ";;\t nscount    = {$this->nscount}\n";
        $output .= ";;\t arcount    = {$this->arcount}\n";

        return $output;
    }

    /**
     * @throws \Net\DNS2\Exception
     */
    public function set(\Net\DNS2\Packet\Packet &$packet): bool
    {
        if ($packet->rdlength < \Net\DNS2\Lookups::DNS_HEADER_SIZE) {
            throw new Exception(
                'invalid header data provided; too small',
                \Net\DNS2\Lookups::E_HEADER_INVALID
            );
        }

        $offset = 0;

        $this->id = ord($packet->rdata[$offset]) << 8 | ord($packet->rdata[++$offset]);

        ++$offset;
        $this->qr     = (ord($packet->rdata[$offset]) >> 7) & 0x1;
        $this->opcode = (ord($packet->rdata[$offset]) >> 3) & 0xf;
        $this->aa     = (ord($packet->rdata[$offset]) >> 2) & 0x1;
        $this->tc     = (ord($packet->rdata[$offset]) >> 1) & 0x1;
        $this->rd     = ord($packet->rdata[$offset]) & 0x1;

        ++$offset;
        $this->ra    = (ord($packet->rdata[$offset]) >> 7) & 0x1;
        $this->z     = (ord($packet->rdata[$offset]) >> 6) & 0x1;
        $this->ad    = (ord($packet->rdata[$offset]) >> 5) & 0x1;
        $this->cd    = (ord($packet->rdata[$offset]) >> 4) & 0x1;
        $this->rcode = ord($packet->rdata[$offset]) & 0xf;

        $this->qdcount = ord($packet->rdata[++$offset]) << 8 | ord($packet->rdata[++$offset]);
        $this->ancount = ord($packet->rdata[++$offset]) << 8 | ord($packet->rdata[++$offset]);
        $this->nscount = ord($packet->rdata[++$offset]) << 8 | ord($packet->rdata[++$offset]);
        $this->arcount = ord($packet->rdata[++$offset]) << 8 | ord($packet->rdata[++$offset]);

        $packet->offset += \Net\DNS2\Lookups::DNS_HEADER_SIZE;

        return true;
    }

    public function get(\Net\DNS2\Packet\Packet &$packet): string
    {
        $packet->offset += \Net\DNS2\Lookups::DNS_HEADER_SIZE;

        return pack('n', $this->id) .
            chr(($this->qr << 7) | ($this->opcode << 3) | ($this->aa << 2) | ($this->tc << 1) | $this->rd) .
            chr(($this->ra << 7) | ($this->ad << 5) | ($this->cd << 4) | $this->rcode) .
            pack('n4', $this->qdcount, $this->ancount, $this->nscount, $this->arcount);
    }
}
