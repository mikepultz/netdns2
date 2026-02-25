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
class Net_DNS2_RR_SOA extends Net_DNS2_RR
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
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $offset = $packet->offset;

            $this->mname = Net_DNS2_Packet::expand($packet, $offset);
            $this->rname = Net_DNS2_Packet::expand($packet, $offset, true);

            $x = unpack(
                '@' . $offset . '/Nserial/Nrefresh/Nretry/Nexpire/Nminimum/',
                $packet->rdata
            );

            $this->serial  = Net_DNS2::expandUint32($x['serial']);
            $this->refresh = Net_DNS2::expandUint32($x['refresh']);
            $this->retry   = Net_DNS2::expandUint32($x['retry']);
            $this->expire  = Net_DNS2::expandUint32($x['expire']);
            $this->minimum = Net_DNS2::expandUint32($x['minimum']);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
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
