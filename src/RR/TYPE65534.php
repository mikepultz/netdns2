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
 * TYPE65534 - Private space (Bind 9.8+ signing process state)
 */
class TYPE65534 extends RR
{
    public string $private_data = '';

    #[\Override]
    protected function rrToString(): string
    {
        return base64_encode($this->private_data);
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->private_data = base64_decode(implode('', $rdata));

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $this->private_data = $this->rdata;

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->private_data) > 0) {

            $data = $this->private_data;

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
