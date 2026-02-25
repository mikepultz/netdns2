<?php declare(strict_types=1);

namespace Net\DNS2;

use Net\DNS2\Packet\Request;
use Net\DNS2\Packet\Response;
use Net\DNS2\RR\RR;
use Net\DNS2\RR\SIG;
use Net\DNS2\RR\TSIG;

class Notifier extends DNS2
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
        $this->packet->header->opcode = Lookups::OPCODE_NOTIFY;
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

    /**
     * @throws Exception
     */
    public function add(RR $rr): bool
    {
        $this->checkName($rr->name);

        if (!in_array($rr, $this->packet->answer)) {
            $this->packet->answer[] = $rr;
        }

        return true;
    }

    #[\Deprecated('Use signTSIG() instead')]
    public function signature(string $keyname, string $signature, string $algorithm = TSIG::HMAC_MD5): bool
    {
        return $this->signTSIG($keyname, $signature, $algorithm);
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
    public function notify(?Response &$response = null): bool
    {
        if ($this->auth_signature instanceof TSIG
            || $this->auth_signature instanceof SIG
        ) {
            $this->packet->additional[] = $this->auth_signature;
        }

        $this->packet->header->qdcount = count($this->packet->question);
        $this->packet->header->ancount = count($this->packet->answer);
        $this->packet->header->nscount = count($this->packet->authority);
        $this->packet->header->arcount = count($this->packet->additional);

        if ($this->packet->header->qdcount === 0) {
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
