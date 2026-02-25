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

class Net_DNS2_Resolver extends Net_DNS2
{
    public function __construct(?array $options = null)
    {
        parent::__construct($options);
    }

    /**
     * @throws Net_DNS2_Exception
     */
    public function query(string $name, string $type = 'A', string $class = 'IN'): Net_DNS2_Packet_Response
    {
        $this->checkServers(Net_DNS2::RESOLV_CONF);

        if ($type === 'IXFR') {
            $type = 'AXFR';
        }

        if (!str_contains($name, '.') && $type !== 'PTR') {
            $name .= '.' . strtolower($this->domain);
        }

        $packet = new Net_DNS2_Packet_Request($name, $type, $class);

        if ($this->auth_signature instanceof Net_DNS2_RR_TSIG
            || $this->auth_signature instanceof Net_DNS2_RR_SIG
        ) {
            $packet->additional[]    = $this->auth_signature;
            $packet->header->arcount = count($packet->additional);
        }

        if ($this->dnssec) {
            $opt = new Net_DNS2_RR_OPT();
            $opt->do    = 1;
            $opt->class = $this->dnssec_payload_size;

            $packet->additional[]    = $opt;
            $packet->header->arcount = count($packet->additional);
        }

        if ($this->dnssec_ad_flag) {
            $packet->header->ad = 1;
        }
        if ($this->dnssec_cd_flag) {
            $packet->header->cd = 1;
        }

        $packet_hash = '';

        if ($this->use_cache && $this->cacheable($type)) {
            $this->cache->open($this->cache_file, $this->cache_size, $this->cache_serializer);

            $packet_hash = md5($packet->question[0]->qname . '|' . $packet->question[0]->qtype);

            if ($this->cache->has($packet_hash)) {
                return $this->cache->get($packet_hash);
            }
        }

        $packet->header->rd = $this->recurse ? 1 : 0;

        $response = $this->sendPacket($packet, $type === 'AXFR' || $this->use_tcp);

        if ($this->strict_query_mode && $response->header->ancount > 0) {
            $found = false;

            foreach ($response->answer as $object) {
                if (strcasecmp(trim($object->name, '.'), trim($packet->question[0]->qname, '.')) === 0
                    && $object->type === $packet->question[0]->qtype
                    && $object->class === $packet->question[0]->qclass
                ) {
                    $found = true;
                    break;
                }
            }

            if (!$found) {
                $response->answer = [];
                $response->header->ancount = 0;
            }
        }

        if ($this->use_cache && $this->cacheable($type)) {
            $this->cache->put($packet_hash, $response);
        }

        return $response;
    }

    /**
     * @throws Net_DNS2_Exception
     */
    public function iquery(Net_DNS2_RR $rr): Net_DNS2_Packet_Response
    {
        $this->checkServers(Net_DNS2::RESOLV_CONF);

        $packet = new Net_DNS2_Packet_Request($rr->name, 'A', 'IN');
        $packet->question = [];
        $packet->header->qdcount = 0;
        $packet->header->opcode  = Net_DNS2_Lookups::OPCODE_IQUERY;
        $packet->answer[]        = $rr;
        $packet->header->ancount = 1;

        if ($this->auth_signature instanceof Net_DNS2_RR_TSIG
            || $this->auth_signature instanceof Net_DNS2_RR_SIG
        ) {
            $packet->additional[]    = $this->auth_signature;
            $packet->header->arcount = count($packet->additional);
        }

        return $this->sendPacket($packet, $this->use_tcp);
    }
}
