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
 * A Resource Record - RFC1035 section 3.4.1
 */
class Net_DNS2_RR_A extends Net_DNS2_RR
{
    public string $address = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->address;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $value = array_shift($rdata);

        if (Net_DNS2::isIPv4($value) === true) {
            $this->address = $value;
            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $this->address = inet_ntop($this->rdata);
            if ($this->address !== false) {
                return true;
            }
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        $packet->offset += 4;
        return inet_pton($this->address);
    }
}
