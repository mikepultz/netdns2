<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * KX Resource Record - RFC2230 section 3.1
 *
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                  PREFERENCE                   |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   /                   EXCHANGER                   /
 *   /                                               /
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class KX extends RR
{
    public int $preference = 0;
    public string $exchange = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->preference . ' ' . $this->cleanString($this->exchange) . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->preference = (int) array_shift($rdata);
        $this->exchange   = $this->cleanString(array_shift($rdata));

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('npreference', $this->rdata);
            $this->preference = $x['preference'];

            $offset = $packet->offset + 2;
            $this->exchange = Packet::label($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->exchange) > 0) {
            $data = pack('nC', $this->preference, strlen($this->exchange)) .
                $this->exchange;

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
