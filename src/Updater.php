<?php declare(strict_types=1);

namespace Net\DNS2;

use Net\DNS2\Packet\Request;
use Net\DNS2\Packet\Response;
use Net\DNS2\RR\ANY;
use Net\DNS2\RR\RR;
use Net\DNS2\RR\SIG;
use Net\DNS2\RR\TSIG;

class Updater extends DNS2
{
    private Request $packet;

    /**
     * @throws Exception
     */
    public function __construct(string $zone, ?array $options = null)
    {
        parent::__construct($options);

        $this->packet = new Packet\Request(
            strtolower(trim($zone, " \n\r\t.")), 'SOA', 'IN'
        );
        $this->packet->header->opcode = Lookups::OPCODE_UPDATE;
    }

    /**
     * @throws Exception
     */
    private function checkName(string $name): bool
    {
        if (!preg_match('/' . $this->packet->question[0]->qname . '$/', $name)) {
            throw new Exception(
                "name provided ({$name}) does not match zone name ({$this->packet->question[0]->qname})",
                Lookups::E_PACKET_INVALID
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
     * @throws Exception
     */
    public function add(RR $rr): bool
    {
        $this->checkName($rr->name);

        if (!in_array($rr, $this->packet->authority)) {
            $this->packet->authority[] = $rr;
        }

        return true;
    }

    /**
     * @throws Exception
     */
    public function delete(RR $rr): bool
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
     * @throws Exception
     */
    public function deleteAny(string $name, string $type): bool
    {
        $this->checkName($name);

        $class = Lookups::$rr_types_id_to_class[Lookups::$rr_types_by_name[$type]] ?? null;
        if ($class === null) {
            throw new Exception(
                "unknown or un-supported resource record type: {$type}",
                Lookups::E_RR_INVALID
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
     * @throws Exception
     */
    public function deleteAll(string $name): bool
    {
        $this->checkName($name);

        $rr = new ANY();
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
     * @throws Exception
     */
    public function checkExists(string $name, string $type): bool
    {
        $this->checkName($name);

        $class = Lookups::$rr_types_id_to_class[Lookups::$rr_types_by_name[$type]] ?? null;
        if ($class === null) {
            throw new Exception(
                "unknown or un-supported resource record type: {$type}",
                Lookups::E_RR_INVALID
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
     * @throws Exception
     */
    public function checkValueExists(RR $rr): bool
    {
        $this->checkName($rr->name);
        $rr->ttl = 0;

        if (!in_array($rr, $this->packet->answer)) {
            $this->packet->answer[] = $rr;
        }

        return true;
    }

    /**
     * @throws Exception
     */
    public function checkNotExists(string $name, string $type): bool
    {
        $this->checkName($name);

        $class = Lookups::$rr_types_id_to_class[Lookups::$rr_types_by_name[$type]] ?? null;
        if ($class === null) {
            throw new Exception(
                "unknown or un-supported resource record type: {$type}",
                Lookups::E_RR_INVALID
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
     * @throws Exception
     */
    public function checkNameInUse(string $name): bool
    {
        $this->checkName($name);

        $rr = new ANY();
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
     * @throws Exception
     */
    public function checkNameNotInUse(string $name): bool
    {
        $this->checkName($name);

        $rr = new ANY();
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

    public function packet(): Request
    {
        $p = $this->packet;

        if ($this->auth_signature instanceof TSIG
            || $this->auth_signature instanceof SIG
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
     * @throws Exception
     */
    public function update(?Response &$response = null): bool
    {
        $this->checkServers(DNS2::RESOLV_CONF);

        if ($this->auth_signature instanceof TSIG
            || $this->auth_signature instanceof SIG
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
                Lookups::E_PACKET_INVALID
            );
        }

        $response = $this->sendPacket($this->packet, $this->use_tcp);
        $this->packet->reset();

        return true;
    }
}
