<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * AFSDB Resource Record - RFC1183 section 1
 */
class AFSDB extends RR
{
    public int $subtype = 0;
    public string $hostname = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->subtype . ' ' . $this->cleanString($this->hostname) . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->subtype  = (int) array_shift($rdata);
        $this->hostname = $this->cleanString(array_shift($rdata));

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('nsubtype', $this->rdata);

            $this->subtype  = $x['subtype'];
            $offset         = $packet->offset + 2;

            $this->hostname = Packet::expand($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->hostname) > 0) {
            $data = pack('n', $this->subtype);
            $packet->offset += 2;

            $data .= $packet->compress($this->hostname, $packet->offset);

            return $data;
        }

        return null;
    }
}
