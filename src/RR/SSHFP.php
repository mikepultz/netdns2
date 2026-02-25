<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Packet\Packet;

/**
 * SSHFP Resource Record - RFC4255 section 3.1
 *
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |   algorithm   |    fp type    |                               /
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
 *      /                                                               /
 *      /                          fingerprint                          /
 *      /                                                               /
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class SSHFP extends RR
{
    public int $algorithm = 0;
    public int $fp_type = 0;
    public string $fingerprint = '';

    const SSHFP_ALGORITHM_RES     = 0;
    const SSHFP_ALGORITHM_RSA     = 1;
    const SSHFP_ALGORITHM_DSS     = 2;
    const SSHFP_ALGORITHM_ECDSA   = 3;
    const SSHFP_ALGORITHM_ED25519 = 4;

    const SSHFP_FPTYPE_RES    = 0;
    const SSHFP_FPTYPE_SHA1   = 1;
    const SSHFP_FPTYPE_SHA256 = 2;

    #[\Override]
    protected function rrToString(): string
    {
        return $this->algorithm . ' ' . $this->fp_type . ' ' . $this->fingerprint;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        // "The use of mnemonics instead of numbers is not allowed." - RFC4255 section 3.2
        $algorithm   = (int)array_shift($rdata);
        $fp_type     = (int)array_shift($rdata);
        $fingerprint = strtolower(implode('', $rdata));

        if ($algorithm !== self::SSHFP_ALGORITHM_RSA
            && $algorithm !== self::SSHFP_ALGORITHM_DSS
            && $algorithm !== self::SSHFP_ALGORITHM_ECDSA
            && $algorithm !== self::SSHFP_ALGORITHM_ED25519
        ) {
            return false;
        }

        if ($fp_type !== self::SSHFP_FPTYPE_SHA1
            && $fp_type !== self::SSHFP_FPTYPE_SHA256
        ) {
            return false;
        }

        $this->algorithm   = $algorithm;
        $this->fp_type     = $fp_type;
        $this->fingerprint = $fingerprint;

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $x = unpack('Calgorithm/Cfp_type', $this->rdata);

            $this->algorithm = $x['algorithm'];
            $this->fp_type   = $x['fp_type'];

            if ($this->algorithm !== self::SSHFP_ALGORITHM_RSA
                && $this->algorithm !== self::SSHFP_ALGORITHM_DSS
                && $this->algorithm !== self::SSHFP_ALGORITHM_ECDSA
                && $this->algorithm !== self::SSHFP_ALGORITHM_ED25519
            ) {
                return false;
            }

            if ($this->fp_type !== self::SSHFP_FPTYPE_SHA1
                && $this->fp_type !== self::SSHFP_FPTYPE_SHA256
            ) {
                return false;
            }

            $fp = unpack('H*a', substr($this->rdata, 2));
            $this->fingerprint = strtolower($fp['a']);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->fingerprint) > 0) {

            $data = pack(
                'CCH*', $this->algorithm, $this->fp_type, $this->fingerprint
            );

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
