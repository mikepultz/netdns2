<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * DHCID Resource Record - RFC4701 section 3.1
 */
class DHCID extends RR
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
    protected function rrSet(Packet &$packet): bool
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
    protected function rrGet(Packet &$packet): ?string
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
