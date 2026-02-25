<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * TYPE65534 - Private space (Bind 9.8+ signing process state)
 */
class TYPE65534 extends RR
{
    public string $private_data = '';

    #[\Override]
    protected function rrToString(): string
    {
        return base64_encode($this->private_data);
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->private_data = base64_decode(implode('', $rdata));

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $this->private_data = $this->rdata;

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->private_data) > 0) {

            $data = $this->private_data;

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
