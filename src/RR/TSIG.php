<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\DNS2;
use Net\DNS2\Lookups;
use Net\DNS2\Exception;
use Net\DNS2\Packet\Packet;
use Net\DNS2\Packet\Request;

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 */

/**
 * TSIG Resource Record - RFC 2845
 *
 *      0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     /                          algorithm                            /
 *     /                                                               /
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                          time signed                          |
 *     |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                               |              fudge            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |            mac size           |                               /
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
 *     /                              mac                              /
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |           original id         |              error            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |          other length         |                               /
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
 *     /                          other data                           /
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class TSIG extends RR
{
    const HMAC_MD5    = 'hmac-md5.sig-alg.reg.int';   // RFC 2845, required
    const GSS_TSIG    = 'gss-tsig';                   // unsupported, optional
    const HMAC_SHA1   = 'hmac-sha1';                  // RFC 4635, required
    const HMAC_SHA224 = 'hmac-sha224';                // RFC 4635, optional
    const HMAC_SHA256 = 'hmac-sha256';                // RFC 4635, required
    const HMAC_SHA384 = 'hmac-sha384';                // RFC 4635, optional
    const HMAC_SHA512 = 'hmac-sha512';                // RFC 4635, optional

    /** @var array<string, string> */
    public static array $hash_algorithms = [
        self::HMAC_MD5    => 'md5',
        self::HMAC_SHA1   => 'sha1',
        self::HMAC_SHA224 => 'sha224',
        self::HMAC_SHA256 => 'sha256',
        self::HMAC_SHA384 => 'sha384',
        self::HMAC_SHA512 => 'sha512',
    ];

    public string $algorithm = '';
    public int $time_signed = 0;
    public int $fudge = 0;
    public int $mac_size = 0;
    public string $mac = '';
    public int $original_id = 0;
    public int $error = 0;
    public int $other_length = 0;
    public string|int $other_data = '';
    public string $key = '';

    #[\Override]
    protected function rrToString(): string
    {
        $out = $this->cleanString($this->algorithm) . '. ' .
            $this->time_signed . ' ' .
            $this->fudge . ' ' . $this->mac_size . ' ' .
            base64_encode($this->mac) . ' ' . $this->original_id . ' ' .
            $this->error . ' ' . $this->other_length;

        if ($this->other_length > 0) {
            $out .= ' ' . $this->other_data;
        }

        return $out;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->key = preg_replace('/\s+/', '', array_shift($rdata));

        // per RFC 2845 section 2.3
        $this->algorithm    = self::HMAC_MD5;
        $this->time_signed  = time();
        $this->fudge        = 300;
        $this->mac_size     = 0;
        $this->mac          = '';
        $this->original_id  = 0;
        $this->error        = 0;
        $this->other_length = 0;
        $this->other_data   = '';

        $this->class = 'ANY';
        $this->ttl   = 0;

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $newoffset       = $packet->offset;
            $this->algorithm = Packet::expand($packet, $newoffset);
            $offset          = $newoffset - $packet->offset;

            $x = unpack(
                '@' . $offset . '/ntime_high/Ntime_low/nfudge/nmac_size',
                $this->rdata
            );

            $this->time_signed = DNS2::expandUint32($x['time_low']);
            $this->fudge       = $x['fudge'];
            $this->mac_size    = $x['mac_size'];

            $offset += 10;

            if ($this->mac_size > 0) {
                $this->mac = substr($this->rdata, $offset, $this->mac_size);
                $offset += $this->mac_size;
            }

            $x = unpack(
                '@' . $offset . '/noriginal_id/nerror/nother_length',
                $this->rdata
            );

            $this->original_id  = $x['original_id'];
            $this->error        = $x['error'];
            $this->other_length = $x['other_length'];

            // the only time there is "other data" is BADTIME error
            // other length should be 6, data is server's current time - RFC 2845 section 4.5.2
            if ($this->error === Lookups::RCODE_BADTIME) {

                if ($this->other_length !== 6) {
                    return false;
                }

                $x = unpack(
                    'nhigh/nlow',
                    substr($this->rdata, $offset + 6, $this->other_length)
                );
                $this->other_data = $x['low'];
            }

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->key) > 0) {

            $new_packet = new Request('example.com', 'SOA', 'IN');
            $new_packet->copy($packet);

            array_pop($new_packet->additional);
            $new_packet->header->arcount = count($new_packet->additional);

            $sig_data = $new_packet->get();

            $sig_data .= Packet::pack($this->name);

            $sig_data .= pack(
                'nN', Lookups::$classes_by_name[$this->class], $this->ttl
            );

            $sig_data .= Packet::pack(strtolower($this->algorithm));

            $sig_data .= pack(
                'nNnnn', 0, $this->time_signed, $this->fudge,
                $this->error, $this->other_length
            );
            if ($this->other_length > 0) {
                $sig_data .= pack('nN', 0, $this->other_data);
            }

            $this->mac = $this->_signHMAC(
                $sig_data, base64_decode($this->key), $this->algorithm
            );
            $this->mac_size = strlen($this->mac);

            $data = Packet::pack(strtolower($this->algorithm));

            $data .= pack(
                'nNnn', 0, $this->time_signed, $this->fudge, $this->mac_size
            );
            $data .= $this->mac;

            if ($this->error === Lookups::RCODE_BADTIME) {
                $this->other_length = strlen($this->other_data);
                if ($this->other_length !== 6) {
                    return null;
                }
            } else {
                $this->other_length = 0;
                $this->other_data = '';
            }

            $data .= pack(
                'nnn', $packet->header->id, $this->error, $this->other_length
            );
            if ($this->other_length > 0) {
                $data .= pack('nN', 0, $this->other_data);
            }

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }

    private function _signHMAC(string $data, ?string $key = null, string $algorithm = self::HMAC_MD5): string
    {
        if (extension_loaded('hash')) {

            if (!isset(self::$hash_algorithms[$algorithm])) {
                throw new Exception(
                    'invalid or unsupported algorithm',
                    Lookups::E_PARSE_ERROR
                );
            }

            return hash_hmac(self::$hash_algorithms[$algorithm], $data, $key, true);
        }

        if ($algorithm !== self::HMAC_MD5) {
            throw new Exception(
                'only HMAC-MD5 supported. please install the php-extension ' .
                '"hash" in order to use the sha-family',
                Lookups::E_PARSE_ERROR
            );
        }

        if (is_null($key)) {
            return pack('H*', md5($data));
        }

        $key = str_pad($key, 64, chr(0x00));
        if (strlen($key) > 64) {
            $key = pack('H*', md5($key));
        }

        $k_ipad = $key ^ str_repeat(chr(0x36), 64);
        $k_opad = $key ^ str_repeat(chr(0x5c), 64);

        return $this->_signHMAC(
            $k_opad . pack('H*', md5($k_ipad . $data)), null, $algorithm
        );
    }
}
