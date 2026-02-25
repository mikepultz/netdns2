<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\DNS2;
use Net\DNS2\Packet\Packet;

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 */

/**
 * L32 Resource Record - RFC6742 section 2.2
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Preference           |      Locator32 (16 MSBs)      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Locator32 (16 LSBs)       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class L32 extends RR
{
    public int $preference = 0;
    public string $locator32 = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->preference . ' ' . $this->locator32;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->preference = (int) array_shift($rdata);
        $this->locator32  = array_shift($rdata);

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('npreference/C4locator', $this->rdata);

            $this->preference = $x['preference'];

            $this->locator32 = $x['locator1'] . '.' . $x['locator2'] . '.' .
                $x['locator3'] . '.' . $x['locator4'];

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->locator32) > 0) {
            $n = explode('.', $this->locator32);

            return pack('nC4', $this->preference, $n[0], $n[1], $n[2], $n[3]);
        }

        return null;
    }
}
