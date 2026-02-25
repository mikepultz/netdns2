<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\DNS2;
use Net\DNS2\Packet\Packet;

/**
 * SOA Resource Record - RFC1035 section 3.3.13
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                     MNAME                     /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                     RNAME                     /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    SERIAL                     |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    REFRESH                    |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                     RETRY                     |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    EXPIRE                     |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    MINIMUM                    |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class SOA extends RR
{
    public string $mname = '';
    public string $rname = '';
    public int $serial = 0;
    public int $refresh = 0;
    public int $retry = 0;
    public int $expire = 0;
    public int $minimum = 0;

    #[\Override]
    protected function rrToString(): string
    {
        return $this->cleanString($this->mname) . '. ' .
            $this->cleanString($this->rname) . '. ' .
            $this->serial . ' ' . $this->refresh . ' ' . $this->retry . ' ' .
            $this->expire . ' ' . $this->minimum;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->mname   = $this->cleanString($rdata[0]);
        $this->rname   = $this->cleanString($rdata[1]);

        $this->serial  = (int)$rdata[2];
        $this->refresh = (int)$rdata[3];
        $this->retry   = (int)$rdata[4];
        $this->expire  = (int)$rdata[5];
        $this->minimum = (int)$rdata[6];

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $offset = $packet->offset;

            $this->mname = Packet::expand($packet, $offset);
            $this->rname = Packet::expand($packet, $offset, true);

            $x = unpack(
                '@' . $offset . '/Nserial/Nrefresh/Nretry/Nexpire/Nminimum/',
                $packet->rdata
            );

            $this->serial  = DNS2::expandUint32($x['serial']);
            $this->refresh = DNS2::expandUint32($x['refresh']);
            $this->retry   = DNS2::expandUint32($x['retry']);
            $this->expire  = DNS2::expandUint32($x['expire']);
            $this->minimum = DNS2::expandUint32($x['minimum']);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->mname) > 0) {

            $data = $packet->compress($this->mname, $packet->offset);
            $data .= $packet->compress($this->rname, $packet->offset);

            $data .= pack(
                'N5', $this->serial, $this->refresh, $this->retry,
                $this->expire, $this->minimum
            );

            $packet->offset += 20;

            return $data;
        }

        return null;
    }
}
