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
 * URI Resource Record - http://tools.ietf.org/html/draft-faltstrom-uri-06
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          Priority             |          Weight               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   /                                                               /
 *   /                             Target                            /
 *   /                                                               /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class Net_DNS2_RR_URI extends Net_DNS2_RR
{
    public int $priority = 0;
    public int $weight = 0;
    public string $target = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->priority . ' ' . $this->weight . ' "' . $this->target . '"';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->priority = (int)$rdata[0];
        $this->weight   = (int)$rdata[1];
        $this->target   = trim(strtolower(trim($rdata[2])), '"');

        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $x = unpack('npriority/nweight/a*target', $this->rdata);

            $this->priority = $x['priority'];
            $this->weight   = $x['weight'];
            $this->target   = $x['target'];

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if (strlen($this->target) > 0) {

            $data = pack('nna*', $this->priority, $this->weight, $this->target);

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
