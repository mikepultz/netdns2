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

class Net_DNS2_Notifier extends Net_DNS2
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
        $this->packet->header->opcode = Net_DNS2_Lookups::OPCODE_NOTIFY;
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

    /**
     * @throws Net_DNS2_Exception
     */
    public function add(Net_DNS2_RR $rr): bool
    {
        $this->checkName($rr->name);

        if (!in_array($rr, $this->packet->answer)) {
            $this->packet->answer[] = $rr;
        }

        return true;
    }

    #[\Deprecated('Use signTSIG() instead')]
    public function signature(string $keyname, string $signature, string $algorithm = Net_DNS2_RR_TSIG::HMAC_MD5): bool
    {
        return $this->signTSIG($keyname, $signature, $algorithm);
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
    public function notify(?Net_DNS2_Packet_Response &$response = null): bool
    {
        if ($this->auth_signature instanceof Net_DNS2_RR_TSIG
            || $this->auth_signature instanceof Net_DNS2_RR_SIG
        ) {
            $this->packet->additional[] = $this->auth_signature;
        }

        $this->packet->header->qdcount = count($this->packet->question);
        $this->packet->header->ancount = count($this->packet->answer);
        $this->packet->header->nscount = count($this->packet->authority);
        $this->packet->header->arcount = count($this->packet->additional);

        if ($this->packet->header->qdcount === 0) {
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
