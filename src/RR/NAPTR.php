<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * NAPTR Resource Record - RFC2915
 *
 *      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                     ORDER                     |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                   PREFERENCE                  |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   /                     FLAGS                     /
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   /                   SERVICES                    /
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   /                    REGEXP                     /
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   /                  REPLACEMENT                  /
 *   /                                               /
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class NAPTR extends RR
{
    public int $order = 0;
    public int $preference = 0;
    public string $flags = '';
    public string $services = '';
    public string $regexp = '';
    public string $replacement = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->order . ' ' . $this->preference . ' ' .
            $this->formatString($this->flags) . ' ' .
            $this->formatString($this->services) . ' ' .
            $this->formatString($this->regexp) . ' ' .
            $this->cleanString($this->replacement) . '.';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->order      = (int)array_shift($rdata);
        $this->preference = (int)array_shift($rdata);

        $data = $this->buildString($rdata);
        if (count($data) === 4) {

            $this->flags       = $data[0];
            $this->services    = $data[1];
            $this->regexp      = $data[2];
            $this->replacement = $this->cleanString($data[3]);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $x = unpack('norder/npreference', $this->rdata);

            $this->order      = $x['order'];
            $this->preference = $x['preference'];

            $offset = $packet->offset + 4;

            $this->flags       = Packet::label($packet, $offset);
            $this->services    = Packet::label($packet, $offset);
            $this->regexp      = Packet::label($packet, $offset);

            $this->replacement = Packet::expand($packet, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (isset($this->order) && strlen($this->services) > 0) {

            $data = pack('nn', $this->order, $this->preference);

            $data .= chr(strlen($this->flags)) . $this->flags;
            $data .= chr(strlen($this->services)) . $this->services;
            $data .= chr(strlen($this->regexp)) . $this->regexp;

            $packet->offset += strlen($data);

            $data .= $packet->compress($this->replacement, $packet->offset);

            return $data;
        }

        return null;
    }
}
