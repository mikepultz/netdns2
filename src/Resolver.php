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

class Resolver extends DNS2
{
    public function __construct(?array $options = null)
    {
        parent::__construct($options);
    }

    /**
     * @throws \Net\DNS2\Exception
     */
    public function query(string $name, string $type = 'A', string $class = 'IN'): \Net\DNS2\Packet\Response
    {
        $this->checkServers(\Net\DNS2\DNS2::RESOLV_CONF);

        if ($type === 'IXFR') {
            $type = 'AXFR';
        }

        if (!str_contains($name, '.') && $type !== 'PTR') {
            $name .= '.' . strtolower($this->domain);
        }

        $packet = new Packet\Request($name, $type, $class);

        if ($this->auth_signature instanceof \Net\DNS2\RR\TSIG
            || $this->auth_signature instanceof \Net\DNS2\RR\SIG
        ) {
            $packet->additional[]    = $this->auth_signature;
            $packet->header->arcount = count($packet->additional);
        }

        if ($this->dnssec) {
            $opt = new \Net\DNS2\RR\OPT();
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
     * @throws \Net\DNS2\Exception
     */
    public function iquery(\Net\DNS2\RR\RR $rr): \Net\DNS2\Packet\Response
    {
        $this->checkServers(\Net\DNS2\DNS2::RESOLV_CONF);

        $packet = new Packet\Request($rr->name, 'A', 'IN');
        $packet->question = [];
        $packet->header->qdcount = 0;
        $packet->header->opcode  = \Net\DNS2\Lookups::OPCODE_IQUERY;
        $packet->answer[]        = $rr;
        $packet->header->ancount = 1;

        if ($this->auth_signature instanceof \Net\DNS2\RR\TSIG
            || $this->auth_signature instanceof \Net\DNS2\RR\SIG
        ) {
            $packet->additional[]    = $this->auth_signature;
            $packet->header->arcount = count($packet->additional);
        }

        return $this->sendPacket($packet, $this->use_tcp);
    }
}
