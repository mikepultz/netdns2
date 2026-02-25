<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\DNS2;
use Net\DNS2\Packet\Packet;

/**
 * A Resource Record - RFC1035 section 3.4.1
 */
class A extends RR
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

        if (DNS2::isIPv4($value) === true) {
            $this->address = $value;
            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
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
    protected function rrGet(Packet &$packet): ?string
    {
        $packet->offset += 4;
        return inet_pton($this->address);
    }
}
