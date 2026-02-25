<?php declare(strict_types=1);

namespace Net\DNS2;


use Net\DNS2\Packet\Request;
use Net\DNS2\Packet\Response;
use Net\DNS2\RR\RR;
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

class Updater extends DNS2
{
    private \Net\DNS2\Packet\Request $packet;

    /**
     * @throws \Net\DNS2\Exception
     */
    public function __construct(string $zone, ?array $options = null)
    {
        parent::__construct($options);

        $this->packet = new Packet\Request(
            strtolower(trim($zone, " \n\r\t.")), 'SOA', 'IN'
        );
        $this->packet->header->opcode = \Net\DNS2\Lookups::OPCODE_UPDATE;
    }

    /**
     * @throws \Net\DNS2\Exception
     */
    private function checkName(string $name): bool
    {
        if (!preg_match('/' . $this->packet->question[0]->qname . '$/', $name)) {
            throw new Exception(
                "name provided ({$name}) does not match zone name ({$this->packet->question[0]->qname})",
                \Net\DNS2\Lookups::E_PACKET_INVALID
            );
        }

        return true;
    }

    #[\Deprecated('Use signTSIG() instead')]
    public function signature(string $keyname, string $signature): bool
    {
        return $this->signTSIG($keyname, $signature);
    }

    /**
     * @throws \Net\DNS2\Exception
     */
    public function add(\Net\DNS2\RR\RR $rr): bool
    {
        $this->checkName($rr->name);

        if (!in_array($rr, $this->packet->authority)) {
            $this->packet->authority[] = $rr;
        }

        return true;
    }

    /**
     * @throws \Net\DNS2\Exception
     */
    public function delete(\Net\DNS2\RR\RR $rr): bool
    {
        $this->checkName($rr->name);

        $rr->ttl   = 0;
        $rr->class = 'NONE';

        if (!in_array($rr, $this->packet->authority)) {
            $this->packet->authority[] = $rr;
        }

        return true;
    }

    /**
     * @throws \Net\DNS2\Exception
     */
    public function deleteAny(string $name, string $type): bool
    {
        $this->checkName($name);

        $class = \Net\DNS2\Lookups::$rr_types_id_to_class[\Net\DNS2\Lookups::$rr_types_by_name[$type]] ?? null;
        if ($class === null) {
            throw new Exception(
                "unknown or un-supported resource record type: {$type}",
                \Net\DNS2\Lookups::E_RR_INVALID
            );
        }

        $rr = new $class();
        $rr->name     = $name;
        $rr->ttl      = 0;
        $rr->class    = 'ANY';
        $rr->rdlength = -1;
        $rr->rdata    = '';

        if (!in_array($rr, $this->packet->authority)) {
            $this->packet->authority[] = $rr;
        }

        return true;
    }

    /**
     * @throws \Net\DNS2\Exception
     */
    public function deleteAll(string $name): bool
    {
        $this->checkName($name);

        $rr = new \Net\DNS2\RR\ANY();
        $rr->name     = $name;
        $rr->ttl      = 0;
        $rr->type     = 'ANY';
        $rr->class    = 'ANY';
        $rr->rdlength = -1;
        $rr->rdata    = '';

        if (!in_array($rr, $this->packet->authority)) {
            $this->packet->authority[] = $rr;
        }

        return true;
    }

    /**
     * @throws \Net\DNS2\Exception
     */
    public function checkExists(string $name, string $type): bool
    {
        $this->checkName($name);

        $class = \Net\DNS2\Lookups::$rr_types_id_to_class[\Net\DNS2\Lookups::$rr_types_by_name[$type]] ?? null;
        if ($class === null) {
            throw new Exception(
                "unknown or un-supported resource record type: {$type}",
                \Net\DNS2\Lookups::E_RR_INVALID
            );
        }

        $rr = new $class();
        $rr->name     = $name;
        $rr->ttl      = 0;
        $rr->class    = 'ANY';
        $rr->rdlength = -1;
        $rr->rdata    = '';

        if (!in_array($rr, $this->packet->answer)) {
            $this->packet->answer[] = $rr;
        }

        return true;
    }

    /**
     * @throws \Net\DNS2\Exception
     */
    public function checkValueExists(\Net\DNS2\RR\RR $rr): bool
    {
        $this->checkName($rr->name);
        $rr->ttl = 0;

        if (!in_array($rr, $this->packet->answer)) {
            $this->packet->answer[] = $rr;
        }

        return true;
    }

    /**
     * @throws \Net\DNS2\Exception
     */
    public function checkNotExists(string $name, string $type): bool
    {
        $this->checkName($name);

        $class = \Net\DNS2\Lookups::$rr_types_id_to_class[\Net\DNS2\Lookups::$rr_types_by_name[$type]] ?? null;
        if ($class === null) {
            throw new Exception(
                "unknown or un-supported resource record type: {$type}",
                \Net\DNS2\Lookups::E_RR_INVALID
            );
        }

        $rr = new $class();
        $rr->name     = $name;
        $rr->ttl      = 0;
        $rr->class    = 'NONE';
        $rr->rdlength = -1;
        $rr->rdata    = '';

        if (!in_array($rr, $this->packet->answer)) {
            $this->packet->answer[] = $rr;
        }

        return true;
    }

    /**
     * @throws \Net\DNS2\Exception
     */
    public function checkNameInUse(string $name): bool
    {
        $this->checkName($name);

        $rr = new \Net\DNS2\RR\ANY();
        $rr->name     = $name;
        $rr->ttl      = 0;
        $rr->type     = 'ANY';
        $rr->class    = 'ANY';
        $rr->rdlength = -1;
        $rr->rdata    = '';

        if (!in_array($rr, $this->packet->answer)) {
            $this->packet->answer[] = $rr;
        }

        return true;
    }

    /**
     * @throws \Net\DNS2\Exception
     */
    public function checkNameNotInUse(string $name): bool
    {
        $this->checkName($name);

        $rr = new \Net\DNS2\RR\ANY();
        $rr->name     = $name;
        $rr->ttl      = 0;
        $rr->type     = 'ANY';
        $rr->class    = 'NONE';
        $rr->rdlength = -1;
        $rr->rdata    = '';

        if (!in_array($rr, $this->packet->answer)) {
            $this->packet->answer[] = $rr;
        }

        return true;
    }

    public function packet(): \Net\DNS2\Packet\Request
    {
        $p = $this->packet;

        if ($this->auth_signature instanceof \Net\DNS2\RR\TSIG
            || $this->auth_signature instanceof \Net\DNS2\RR\SIG
        ) {
            $p->additional[] = $this->auth_signature;
        }

        $p->header->qdcount = count($p->question);
        $p->header->ancount = count($p->answer);
        $p->header->nscount = count($p->authority);
        $p->header->arcount = count($p->additional);

        return $p;
    }

    /**
     * @throws \Net\DNS2\Exception
     */
    public function update(?\Net\DNS2\Packet\Response &$response = null): bool
    {
        $this->checkServers(\Net\DNS2\DNS2::RESOLV_CONF);

        if ($this->auth_signature instanceof \Net\DNS2\RR\TSIG
            || $this->auth_signature instanceof \Net\DNS2\RR\SIG
        ) {
            $this->packet->additional[] = $this->auth_signature;
        }

        $this->packet->header->qdcount = count($this->packet->question);
        $this->packet->header->ancount = count($this->packet->answer);
        $this->packet->header->nscount = count($this->packet->authority);
        $this->packet->header->arcount = count($this->packet->additional);

        if ($this->packet->header->qdcount === 0 || $this->packet->header->nscount === 0) {
            throw new Exception(
                'empty headers- nothing to send!',
                \Net\DNS2\Lookups::E_PACKET_INVALID
            );
        }

        $response = $this->sendPacket($this->packet, $this->use_tcp);
        $this->packet->reset();

        return true;
    }
}
