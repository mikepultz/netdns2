<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * EUI48 Resource Record - RFC7043 section 3.1
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          EUI-48 Address                       |
 * |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class EUI48 extends RR
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

        $a = explode('-', $value);
        if (count($a) !== 6) {
            return false;
        }

        foreach ($a as $i) {
            if (ctype_xdigit($i) === false) {
                return false;
            }
        }

        $this->address = strtolower($value);

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('C6', $this->rdata);
            if (count($x) === 6) {
                $this->address = vsprintf('%02x-%02x-%02x-%02x-%02x-%02x', $x);
                return true;
            }
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        $data = '';

        $a = explode('-', $this->address);
        foreach ($a as $b) {
            $data .= chr(hexdec($b));
        }

        $packet->offset += 6;
        return $data;
    }
}
