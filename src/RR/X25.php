<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * X25 Resource Record - RFC1183 section 3.1
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                  PSDN-address                 /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class X25 extends RR
{
    public string $psdnaddress = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->formatString($this->psdnaddress);
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $data = $this->buildString($rdata);
        if (count($data) === 1) {
            $this->psdnaddress = $data[0];
            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $this->psdnaddress = Packet::label($packet, $packet->offset);
            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->psdnaddress) > 0) {

            $data = chr(strlen($this->psdnaddress)) . $this->psdnaddress;

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
