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

class Net_DNS2_Updater extends Net_DNS2
{
    private Net_DNS2_Packet_Request $packet;

    /**
     * @throws Net_DNS2_Exception
     */
    public function __construct(string $zone, ?array $options = null)
    {
        parent::__construct($options);

        $this->packet = new Net_DNS2_Packet_Request(
            strtolower(trim($zone, " \n\r\t.")), 'SOA', 'IN'
        );
        $this->packet->header->opcode = Net_DNS2_Lookups::OPCODE_UPDATE;
    }

    /**
     * @throws Net_DNS2_Exception
     */
    private function checkName(string $name): bool
    {
        if (!preg_match('/' . $this->packet->question[0]->qname . '$/', $name)) {
            throw new Net_DNS2_Exception(
                "name provided ({$name}) does not match zone name ({$this->packet->question[0]->qname})",
                Net_DNS2_Lookups::E_PACKET_INVALID
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
     * @throws Net_DNS2_Exception
     */
    public function add(Net_DNS2_RR $rr): bool
    {
        $this->checkName($rr->name);

        if (!in_array($rr, $this->packet->authority)) {
            $this->packet->authority[] = $rr;
        }

        return true;
    }

    /**
     * @throws Net_DNS2_Exception
     */
    public function delete(Net_DNS2_RR $rr): bool
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
     * @throws Net_DNS2_Exception
     */
    public function deleteAny(string $name, string $type): bool
    {
        $this->checkName($name);

        $class = Net_DNS2_Lookups::$rr_types_id_to_class[Net_DNS2_Lookups::$rr_types_by_name[$type]] ?? null;
        if ($class === null) {
            throw new Net_DNS2_Exception(
                "unknown or un-supported resource record type: {$type}",
                Net_DNS2_Lookups::E_RR_INVALID
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
     * @throws Net_DNS2_Exception
     */
    public function deleteAll(string $name): bool
    {
        $this->checkName($name);

        $rr = new Net_DNS2_RR_ANY();
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
     * @throws Net_DNS2_Exception
     */
    public function checkExists(string $name, string $type): bool
    {
        $this->checkName($name);

        $class = Net_DNS2_Lookups::$rr_types_id_to_class[Net_DNS2_Lookups::$rr_types_by_name[$type]] ?? null;
        if ($class === null) {
            throw new Net_DNS2_Exception(
                "unknown or un-supported resource record type: {$type}",
                Net_DNS2_Lookups::E_RR_INVALID
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
     * @throws Net_DNS2_Exception
     */
    public function checkValueExists(Net_DNS2_RR $rr): bool
    {
        $this->checkName($rr->name);
        $rr->ttl = 0;

        if (!in_array($rr, $this->packet->answer)) {
            $this->packet->answer[] = $rr;
        }

        return true;
    }

    /**
     * @throws Net_DNS2_Exception
     */
    public function checkNotExists(string $name, string $type): bool
    {
        $this->checkName($name);

        $class = Net_DNS2_Lookups::$rr_types_id_to_class[Net_DNS2_Lookups::$rr_types_by_name[$type]] ?? null;
        if ($class === null) {
            throw new Net_DNS2_Exception(
                "unknown or un-supported resource record type: {$type}",
                Net_DNS2_Lookups::E_RR_INVALID
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
     * @throws Net_DNS2_Exception
     */
    public function checkNameInUse(string $name): bool
    {
        $this->checkName($name);

        $rr = new Net_DNS2_RR_ANY();
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
     * @throws Net_DNS2_Exception
     */
    public function checkNameNotInUse(string $name): bool
    {
        $this->checkName($name);

        $rr = new Net_DNS2_RR_ANY();
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

    public function packet(): Net_DNS2_Packet_Request
    {
        $p = $this->packet;

        if ($this->auth_signature instanceof Net_DNS2_RR_TSIG
            || $this->auth_signature instanceof Net_DNS2_RR_SIG
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
     * @throws Net_DNS2_Exception
     */
    public function update(?Net_DNS2_Packet_Response &$response = null): bool
    {
        $this->checkServers(Net_DNS2::RESOLV_CONF);

        if ($this->auth_signature instanceof Net_DNS2_RR_TSIG
            || $this->auth_signature instanceof Net_DNS2_RR_SIG
        ) {
            $this->packet->additional[] = $this->auth_signature;
        }

        $this->packet->header->qdcount = count($this->packet->question);
        $this->packet->header->ancount = count($this->packet->answer);
        $this->packet->header->nscount = count($this->packet->authority);
        $this->packet->header->arcount = count($this->packet->additional);

        if ($this->packet->header->qdcount === 0 || $this->packet->header->nscount === 0) {
            throw new Net_DNS2_Exception(
                'empty headers- nothing to send!',
                Net_DNS2_Lookups::E_PACKET_INVALID
            );
        }

        $response = $this->sendPacket($this->packet, $this->use_tcp);
        $this->packet->reset();

        return true;
    }
}
