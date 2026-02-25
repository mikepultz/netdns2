<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\DNS2;
use Net\DNS2\Lookups;
use Net\DNS2\Packet\Packet;

/**
 * RRSIG Resource Record - RFC4034 section 3.1
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |        Type Covered           |  Algorithm    |     Labels    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Original TTL                          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                      Signature Expiration                     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                      Signature Inception                      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |            Key Tag            |                               /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
 *   /                                                               /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   /                                                               /
 *   /                            Signature                          /
 *   /                                                               /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class RRSIG extends RR
{
    public string $typecovered = '';
    public int $algorithm = 0;
    public int $labels = 0;
    public int $origttl = 0;
    public string $sigexp = '';
    public string $sigincep = '';
    public int $keytag = 0;
    public string $signname = '';
    public string $signature = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->typecovered . ' ' . $this->algorithm . ' ' .
            $this->labels . ' ' . $this->origttl . ' ' .
            $this->sigexp . ' ' . $this->sigincep . ' ' .
            $this->keytag . ' ' . $this->cleanString($this->signname) . '. ' .
            $this->signature;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->typecovered = strtoupper(array_shift($rdata));
        $this->algorithm   = (int)array_shift($rdata);
        $this->labels      = (int)array_shift($rdata);
        $this->origttl     = (int)array_shift($rdata);
        $this->sigexp      = array_shift($rdata);
        $this->sigincep    = array_shift($rdata);
        $this->keytag      = (int)array_shift($rdata);
        $this->signname    = $this->cleanString(array_shift($rdata));

        foreach ($rdata as $line) {
            $this->signature .= $line;
        }

        $this->signature = trim($this->signature);

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $x = unpack(
                'ntc/Calgorithm/Clabels/Norigttl/Nsigexp/Nsigincep/nkeytag',
                $this->rdata
            );

            $this->typecovered = Lookups::$rr_types_by_id[$x['tc']];
            $this->algorithm   = $x['algorithm'];
            $this->labels      = $x['labels'];
            $this->origttl     = DNS2::expandUint32($x['origttl']);

            $this->sigexp   = gmdate('YmdHis', $x['sigexp']);
            $this->sigincep = gmdate('YmdHis', $x['sigincep']);

            $this->keytag = $x['keytag'];

            $offset    = $packet->offset + 18;
            $sigoffset = $offset;

            $this->signname  = strtolower(
                Packet::expand($packet, $sigoffset)
            );
            $this->signature = base64_encode(
                substr($this->rdata, 18 + ($sigoffset - $offset))
            );

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->signature) > 0) {

            preg_match(
                '/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/', $this->sigexp, $e
            );
            preg_match(
                '/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/', $this->sigincep, $i
            );

            $data = pack(
                'nCCNNNn',
                Lookups::$rr_types_by_name[$this->typecovered],
                $this->algorithm,
                $this->labels,
                $this->origttl,
                gmmktime((int)$e[4], (int)$e[5], (int)$e[6], (int)$e[2], (int)$e[3], (int)$e[1]),
                gmmktime((int)$i[4], (int)$i[5], (int)$i[6], (int)$i[2], (int)$i[3], (int)$i[1]),
                $this->keytag
            );

            // the signer name is not allowed to be compressed (see section 3.1.7)
            $names = explode('.', strtolower($this->signname));
            foreach ($names as $name) {
                $data .= chr(strlen($name));
                $data .= $name;
            }
            $data .= "\0";

            $data .= base64_decode($this->signature);

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
