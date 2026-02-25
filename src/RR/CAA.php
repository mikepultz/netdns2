<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * CAA Resource Record - http://tools.ietf.org/html/draft-ietf-pkix-caa-03
 */
class CAA extends RR
{
    public int $flags = 0;
    public string $tag = '';
    public string $value = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->flags . ' ' . $this->tag . ' "' .
            trim($this->cleanString($this->value), '"') . '"';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->flags    = (int) array_shift($rdata);
        $this->tag      = array_shift($rdata);
        $this->value    = trim($this->cleanString(implode(' ', $rdata)), '"');

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('Cflags/Ctag_length', $this->rdata);

            $this->flags    = $x['flags'];
            $offset         = 2;

            $this->tag      = substr($this->rdata, $offset, $x['tag_length']);
            $offset         += $x['tag_length'];

            $this->value    = substr($this->rdata, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->value) > 0) {
            $data  = chr($this->flags);
            $data .= chr(strlen($this->tag)) . $this->tag . $this->value;

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
