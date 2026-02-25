<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * ISDN Resource Record - RFC1183 section 3.2
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                    ISDN-address               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                    SA                         /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class ISDN extends RR
{
    public string $isdnaddress = '';
    public string $sa = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->formatString($this->isdnaddress) . ' ' .
            $this->formatString($this->sa);
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $data = $this->buildString($rdata);
        if (count($data) >= 1) {
            $this->isdnaddress = $data[0];
            if (isset($data[1])) {
                $this->sa = $data[1];
            }

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $this->isdnaddress = Packet::label($packet, $packet->offset);

            if ((strlen($this->isdnaddress) + 1) < $this->rdlength) {
                $this->sa = Packet::label($packet, $packet->offset);
            } else {
                $this->sa = '';
            }

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->isdnaddress) > 0) {
            $data = chr(strlen($this->isdnaddress)) . $this->isdnaddress;
            if (!empty($this->sa)) {
                $data .= chr(strlen($this->sa));
                $data .= $this->sa;
            }

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
