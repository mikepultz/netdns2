<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Lookups;
use Net\DNS2\Packet\Packet;

/**
 * CERT Resource Record - RFC4398 section 2
 */
class CERT extends RR
{
    const CERT_FORMAT_RES       = 0;
    const CERT_FORMAT_PKIX      = 1;
    const CERT_FORMAT_SPKI      = 2;
    const CERT_FORMAT_PGP       = 3;
    const CERT_FORMAT_IPKIX     = 4;
    const CERT_FORMAT_ISPKI     = 5;
    const CERT_FORMAT_IPGP      = 6;
    const CERT_FORMAT_ACPKIX    = 7;
    const CERT_FORMAT_IACPKIX   = 8;
    const CERT_FORMAT_URI       = 253;
    const CERT_FORMAT_OID       = 254;

    /** @var array<string, int> */
    public array $cert_format_name_to_id = [];

    /** @var array<int, string> */
    public array $cert_format_id_to_name = [
        self::CERT_FORMAT_RES       => 'Reserved',
        self::CERT_FORMAT_PKIX      => 'PKIX',
        self::CERT_FORMAT_SPKI      => 'SPKI',
        self::CERT_FORMAT_PGP       => 'PGP',
        self::CERT_FORMAT_IPKIX     => 'IPKIX',
        self::CERT_FORMAT_ISPKI     => 'ISPKI',
        self::CERT_FORMAT_IPGP      => 'IPGP',
        self::CERT_FORMAT_ACPKIX    => 'ACPKIX',
        self::CERT_FORMAT_IACPKIX   => 'IACPKIX',
        self::CERT_FORMAT_URI       => 'URI',
        self::CERT_FORMAT_OID       => 'OID'
    ];

    public int|string $format = 0;
    public int $keytag = 0;
    public int|string $algorithm = 0;
    public string $certificate = '';

    public function __construct(?Packet &$packet = null, ?array $rr = null)
    {
        parent::__construct($packet, $rr);

        $this->cert_format_name_to_id = array_flip($this->cert_format_id_to_name);
    }

    #[\Override]
    protected function rrToString(): string
    {
        return $this->format . ' ' . $this->keytag . ' ' . $this->algorithm .
            ' ' . base64_encode($this->certificate);
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->format = array_shift($rdata);
        if (!is_numeric($this->format)) {
            $mnemonic = strtoupper(trim($this->format));
            if (!isset($this->cert_format_name_to_id[$mnemonic])) {
                return false;
            }

            $this->format = $this->cert_format_name_to_id[$mnemonic];
        } else {
            if (!isset($this->cert_format_id_to_name[$this->format])) {
                return false;
            }
        }

        $this->keytag = (int) array_shift($rdata);

        $this->algorithm = array_shift($rdata);
        if (!is_numeric($this->algorithm)) {
            $mnemonic = strtoupper(trim($this->algorithm));
            if (!isset(Lookups::$algorithm_name_to_id[$mnemonic])) {
                return false;
            }

            $this->algorithm = Lookups::$algorithm_name_to_id[$mnemonic];
        } else {
            if (!isset(Lookups::$algorithm_id_to_name[$this->algorithm])) {
                return false;
            }
        }

        $this->certificate = base64_decode(implode(' ', $rdata));

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('nformat/nkeytag/Calgorithm', $this->rdata);

            $this->format       = $x['format'];
            $this->keytag       = $x['keytag'];
            $this->algorithm    = $x['algorithm'];

            $this->certificate  = substr($this->rdata, 5, $this->rdlength - 5);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->certificate) > 0) {
            $data = pack('nnC', $this->format, $this->keytag, $this->algorithm) . $this->certificate;

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
