<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\DNS2;
use Net\DNS2\Packet\Packet;

/**
 * AAAA Resource Record - RFC1035 section 3.4.1
 */
class AAAA extends RR
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
        if (DNS2::isIPv6($value) === true) {
            $this->address = $value;
            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength === 16) {
            $x = unpack('n8', $this->rdata);
            if (count($x) === 8) {
                $this->address = vsprintf('%x:%x:%x:%x:%x:%x:%x:%x', $x);
                return true;
            }
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        $packet->offset += 16;
        return inet_pton($this->address);
    }
}
