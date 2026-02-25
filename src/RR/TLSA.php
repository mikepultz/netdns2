<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * TLSA Resource Record - RFC 6698
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Cert. Usage  |   Selector    | Matching Type |               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               /
 *  /                                                               /
 *  /                 Certificate Association Data                  /
 *  /                                                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class TLSA extends RR
{
    public int $cert_usage = 0;
    public int $selector = 0;
    public int $matching_type = 0;
    public string $certificate = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->cert_usage . ' ' . $this->selector . ' ' .
            $this->matching_type . ' ' . base64_encode($this->certificate);
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->cert_usage    = (int)array_shift($rdata);
        $this->selector      = (int)array_shift($rdata);
        $this->matching_type = (int)array_shift($rdata);
        $this->certificate   = base64_decode(implode('', $rdata));

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $x = unpack('Cusage/Cselector/Ctype', $this->rdata);

            $this->cert_usage    = $x['usage'];
            $this->selector      = $x['selector'];
            $this->matching_type = $x['type'];

            $this->certificate = substr($this->rdata, 3, $this->rdlength - 3);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->certificate) > 0) {

            $data = pack(
                'CCC', $this->cert_usage, $this->selector, $this->matching_type
            ) . $this->certificate;

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
