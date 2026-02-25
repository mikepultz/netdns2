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
 * HIP Resource Record - RFC5205 section 5
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  HIT length   | PK algorithm  |          PK length            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  ~                           HIT                                 ~
 *  |                                                               |
 *  +                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                     |                                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+                                         +
 *  |                           Public Key                          |
 *  ~                                                               ~
 *  |                                                               |
 *  +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                               |                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *  |                                                               |
 *  ~                       Rendezvous Servers                      ~
 *  |                                                               |
 *  +             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             |
 *  +-+-+-+-+-+-+-+
 */
class Net_DNS2_RR_HIP extends Net_DNS2_RR
{
    public int $hit_length = 0;
    public int $pk_algorithm = 0;
    public int $pk_length = 0;
    public string $hit = '';
    public string $public_key = '';
    public array $rendezvous_servers = [];

    #[\Override]
    protected function rrToString(): string
    {
        $out = $this->pk_algorithm . ' ' .
            $this->hit . ' ' . $this->public_key . ' ';

        foreach ($this->rendezvous_servers as $server) {
            $out .= $server . '. ';
        }

        return trim($out);
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->pk_algorithm = (int) array_shift($rdata);
        $this->hit          = strtoupper(array_shift($rdata));
        $this->public_key   = array_shift($rdata);

        if (count($rdata) > 0) {
            $this->rendezvous_servers = preg_replace('/\.$/', '', $rdata);
        }

        $this->hit_length = strlen(pack('H*', $this->hit));
        $this->pk_length  = strlen(base64_decode($this->public_key));

        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('Chit_length/Cpk_algorithm/npk_length', $this->rdata);

            $this->hit_length   = $x['hit_length'];
            $this->pk_algorithm = $x['pk_algorithm'];
            $this->pk_length    = $x['pk_length'];

            $offset = 4;

            $hit = unpack('H*', substr($this->rdata, $offset, $this->hit_length));

            $this->hit = strtoupper($hit[1]);
            $offset += $this->hit_length;

            $this->public_key = base64_encode(
                substr($this->rdata, $offset, $this->pk_length)
            );
            $offset += $this->pk_length;

            $offset = $packet->offset + $offset;

            while (($offset - $packet->offset) < $this->rdlength) {
                $this->rendezvous_servers[] = Net_DNS2_Packet::expand(
                    $packet, $offset
                );
            }

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if ((strlen($this->hit) > 0) && (strlen($this->public_key) > 0)) {
            $data = pack(
                'CCnH*',
                $this->hit_length,
                $this->pk_algorithm,
                $this->pk_length,
                $this->hit
            );

            $data .= base64_decode($this->public_key);

            $packet->offset += strlen($data);

            foreach ($this->rendezvous_servers as $server) {
                $data .= $packet->compress($server, $packet->offset);
            }

            return $data;
        }

        return null;
    }
}
