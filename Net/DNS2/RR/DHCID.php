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
 * DHCID Resource Record - RFC4701 section 3.1
 */
class Net_DNS2_RR_DHCID extends Net_DNS2_RR
{
    public int $id_type = 0;
    public int $digest_type = 0;
    public string $digest = '';

    #[\Override]
    protected function rrToString(): string
    {
        $out = pack('nC', $this->id_type, $this->digest_type);
        $out .= base64_decode($this->digest);

        return base64_encode($out);
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $data = base64_decode(array_shift($rdata));
        if (strlen($data) > 0) {
            $x = unpack('nid_type/Cdigest_type', $data);

            $this->id_type      = $x['id_type'];
            $this->digest_type  = $x['digest_type'];

            $this->digest = base64_encode(substr($data, 3, strlen($data) - 3));

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('nid_type/Cdigest_type', $this->rdata);

            $this->id_type      = $x['id_type'];
            $this->digest_type  = $x['digest_type'];

            $this->digest = base64_encode(
                substr($this->rdata, 3, $this->rdlength - 3)
            );

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if (strlen($this->digest) > 0) {
            $data = pack('nC', $this->id_type, $this->digest_type) .
                base64_decode($this->digest);

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
