<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * TXT Resource Record - RFC1035 section 3.3.14
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   TXT-DATA                    /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class TXT extends RR
{
    /** @var array<int, string> */
    public array $text = [];

    #[\Override]
    protected function rrToString(): string
    {
        if (count($this->text) === 0) {
            return '""';
        }

        $data = '';

        foreach ($this->text as $t) {
            $data .= $this->formatString($t) . ' ';
        }

        return trim($data);
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $data = $this->buildString($rdata);
        if (count($data) > 0) {
            $this->text = $data;
        }

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $length = $packet->offset + $this->rdlength;
            $offset = $packet->offset;

            while ($length > $offset) {
                $this->text[] = Packet::label($packet, $offset);
            }

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        $data = null;

        foreach ($this->text as $t) {
            $data .= chr(strlen($t)) . $t;
        }

        $packet->offset += strlen($data);

        return $data;
    }
}
