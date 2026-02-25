<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\DNS2;
use Net\DNS2\Lookups;
use Net\DNS2\Exception;
use Net\DNS2\PrivateKey;
use Net\DNS2\Packet\Packet;
use Net\DNS2\Packet\Request;

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 * See LICENSE for more details.
 *
 * This file contains code based off the Net::DNS::SEC Perl module by Olaf M. Kolkman
 *
 * Copyright (c) 2001 - 2005  RIPE NCC.  Author Olaf M. Kolkman
 * Copyright (c) 2007 - 2008  NLnet Labs.  Author Olaf M. Kolkman <olaf@net-dns.org>
 * All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of the author not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 *
 * THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS; IN NO EVENT SHALL
 * AUTHOR BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY
 * DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * SIG Resource Record - RFC2535 section 4.1
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
class SIG extends RR
{
    public ?PrivateKey $private_key = null;

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

        // if the signature is empty and we have a private key + openssl,
        // assume this is a SIG(0) and generate a new signature
        if ((strlen($this->signature) === 0)
            && ($this->private_key instanceof PrivateKey)
            && (extension_loaded('openssl') === true)
        ) {

            $new_packet = new Request('example.com', 'SOA', 'IN');
            $new_packet->copy($packet);

            array_pop($new_packet->additional);
            $new_packet->header->arcount = count($new_packet->additional);

            $sigdata = $data . $new_packet->get();

            $algorithm = match($this->algorithm) {
                Lookups::DNSSEC_ALGORITHM_RSAMD5 => OPENSSL_ALGO_MD5,
                Lookups::DNSSEC_ALGORITHM_RSASHA1 => OPENSSL_ALGO_SHA1,
                Lookups::DNSSEC_ALGORITHM_RSASHA256 => OPENSSL_ALGO_SHA256,
                Lookups::DNSSEC_ALGORITHM_RSASHA512 => OPENSSL_ALGO_SHA512,
                default => throw new Exception(
                    'invalid or unsupported algorithm',
                    Lookups::E_OPENSSL_INV_ALGO
                ),
            };

            if (openssl_sign($sigdata, $this->signature, $this->private_key->instance, $algorithm) === false) {
                throw new Exception(
                    openssl_error_string(),
                    Lookups::E_OPENSSL_ERROR
                );
            }

            switch($this->algorithm) {
                case Lookups::DNSSEC_ALGORITHM_RSAMD5:
                case Lookups::DNSSEC_ALGORITHM_RSASHA1:
                case Lookups::DNSSEC_ALGORITHM_RSASHA256:
                case Lookups::DNSSEC_ALGORITHM_RSASHA512:
                    $this->signature = base64_encode($this->signature);
                    break;
            }
        }

        $data .= base64_decode($this->signature);

        $packet->offset += strlen($data);

        return $data;
    }
}
