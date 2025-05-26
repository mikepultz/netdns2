<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2023, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   NetDNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2023 Mike Pultz <mike@mikepultz.com>
 * @license   https://opensource.org/license/bsd-3-clause/ BSD-3-Clause
 * @link      https://netdns2.com/
 * @since     0.6.0
 *
 */

namespace NetDNS2\RR;

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
 *
 */
final class TSIG extends \NetDNS2\RR
{
    /**
     * TSIG Algorithm Identifiers
     */
    public const HMAC_MD5       = 'hmac-md5.sig-alg.reg.int';   // RFC 2845, required
    public const GSS_TSIG       = 'gss-tsig';                   // unsupported, optional
    public const HMAC_SHA1      = 'hmac-sha1';                  // RFC 4635, required
    public const HMAC_SHA224    = 'hmac-sha224';                // RFC 4635, optional
    public const HMAC_SHA256    = 'hmac-sha256';                // RFC 4635, required
    public const HMAC_SHA384    = 'hmac-sha384';                // RFC 4635, optional
    public const HMAC_SHA512    = 'hmac-sha512';                // RFC 4635, optional

    /**
     * the map of hash values to names
     *
     * @var array<string,string>
     */
    public static array $hash_algorithms = [

        self::HMAC_MD5      => 'md5',
        self::HMAC_SHA1     => 'sha1',
        self::HMAC_SHA224   => 'sha224',
        self::HMAC_SHA256   => 'sha256',
        self::HMAC_SHA384   => 'sha384',
        self::HMAC_SHA512   => 'sha512'
    ];

    /**
     * algorithm used; only supports HMAC-MD5
     */
    protected \NetDNS2\Data\Domain $algorithm;

    /**
     * The time it was signed; this is stored as a string internally to avoid roll-over
     */
    protected string $time_signed;

    /**
     * fudge- allowed offset from the time signed
     */
    protected int $fudge;

    /**
     * size of the digest
     */
    protected int $mac_size;

    /**
     * the digest data
     */
    protected string $mac;

    /**
     * the original id of the request
     */
    protected int $original_id;

    /**
     * additional error code
     */
    protected int $error;

    /**
     * length of the "other" data, should only ever be 0 when there is no error, or 6 when there is the error RCODE_BADTIME
     */
    protected int $other_length;

    /**
     * the other data; should only ever be a timestamp when there is the error RCODE_BADTIME
     */
    protected string $other_data;

    /**
     * the key to use for signing - passed in, not included in the rdata
     */
    protected string $key;

    /**
      * builds a new instance of a TSIG object directly
      */
    public function factory(string $_keyname, string $_algorithm, string $_signature): void
    {
        $this->name      = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC1035, trim($_keyname));
        $this->ttl       = 0;
        $this->class     = \NetDNS2\ENUM\RRClass::set('ANY');
        $this->algorithm = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, $_algorithm);

        $this->rrFromString([ $_signature ]);
    }

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        $out = $this->algorithm . '. ' . $this->time_signed . ' ' . $this->fudge . ' ' . $this->mac_size . ' ' . base64_encode($this->mac) . ' ' . 
            $this->original_id . ' ' . $this->error . ' '. $this->other_length;

        if ($this->other_length > 0)
        {
            $out .= ' ' . $this->other_data;
        }

        return $out;
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        //
        // the only value passed in is the key-
        //
        // this assumes it's passed in base64 encoded.
        //
        $this->key = preg_replace('/\s+/', '', array_shift($_rdata));

        //
        // the rest of the data is set to default
        //
        $this->algorithm    = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, self::HMAC_MD5);
        $this->time_signed  = strval(time());
        $this->fudge        = 300;
        $this->mac_size     = 0;
        $this->mac          = '';
        $this->original_id  = 0;
        $this->error        = 0;
        $this->other_length = 0;
        $this->other_data   = '';

        //
        // per RFC 2845 section 2.3
        //
        $this->class        = \NetDNS2\ENUM\RRClass::set('ANY');
        $this->ttl          = 0;

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrSet()
     */
    protected function rrSet(\NetDNS2\Packet &$_packet): bool
    {
        if ($this->rdlength == 0)
        {
            return false;
        }

        //
        // expand the algorithm
        //
        $offset = 0;
        $this->algorithm = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, $this->rdata, $offset);

        //
        // unpack time, fudge and mac_size
        //
        $val = unpack('nw/Nx/ny/nz', $this->rdata, $offset);
        if ($val === false)
        {
            return false;
        }

        list('w' => $high, 'x' => $low, 'y' => $this->fudge, 'z' => $this->mac_size) = (array)$val;

        $this->time_signed = \NetDNS2\Client::expandUint32($low);
        $offset += 10;

        //
        // copy out the mac
        //
        if ($this->mac_size > 0)
        {
            $this->mac = substr($this->rdata, $offset, $this->mac_size);
            $offset += $this->mac_size;
        }

        //
        // unpack the original id, error, and other_length values
        //
        $val = unpack('nx/ny/nz', $this->rdata, $offset);
        if ($val === false)
        {
            return false;
        }

        list('x' => $this->original_id, 'y' => $this->error, 'z' => $this->other_length) = (array)$val;

        //
        // the only time there is actually any "other data", is when there's a BADTIME error code.
        //
        // The other length should be 6, and the other data field includes the servers current time - per RFC 2845 section 4.5.2
        //
        if ( ($this->error == \NetDNS2\ENUM\RCode::BADTIME->value) && ($this->other_length == 6) )
        {
            //
            // other data is a 48bit timestamp
            //
            $val = unpack('nx/ny', $this->rdata, $offset + 6);
            if ($val === false)
            {
                return false;
            }

            list('x' => $high, 'y' => $this->other_data) = (array)$val;
        }

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if (strlen($this->key) == 0)
        {
            return '';
        }

        //
        // create a new packet for the signature-
        //
        $new_packet = new \NetDNS2\Packet\Request('example.com', 'SOA', 'IN');

        //
        // copy the packet data over
        //
        $new_packet->copy($_packet);

        //
        // remove the TSIG object from the additional list
        //
        array_pop($new_packet->additional);
        $new_packet->header->arcount = count($new_packet->additional);

        //
        // copy out the data
        //
        $sig_data = $new_packet->get();

        //
        // add the name without compressing
        //
        $o = 0;
        $sig_data .= $this->name->encode($o);

        //
        // add the class and TTL
        //
        $sig_data .= pack('nN', $this->class->value, $this->ttl);

        //
        // add the algorithm name without compression
        //
        $sig_data .= $this->algorithm->encode();

        //
        // add the rest of the values
        //
        $sig_data .= pack('nNnnn', 0, $this->time_signed, $this->fudge, $this->error, $this->other_length);

        if ($this->other_length > 0)
        {
            $sig_data .= pack('nN', 0, $this->other_data);
        }

        //
        // base64 decode the key
        //
        $decode = base64_decode($this->key);
        if ($decode === false)
        {
            $decode = '';
        }

        //
        // sign the data
        //
        $this->mac = $this->signHMAC($sig_data, $decode, $this->algorithm);
        $this->mac_size = strlen($this->mac);

        //
        // compress the algorithm
        //
        $data = $this->algorithm->encode();

        //
        // pack the time, fudge and mac size
        //
        $data .= pack('nNnn', 0, $this->time_signed, $this->fudge, $this->mac_size);
        $data .= $this->mac;

        //
        // check the error and other_length
        //
        if ($this->error == \NetDNS2\ENUM\RCode::BADTIME->value)
        {
            $this->other_length = strlen($this->other_data);
            if ($this->other_length != 6)
            {
                return '';
            }

        } else
        {
            $this->other_length = 0;
            $this->other_data = '';
        }

        //
        // pack the id, error and other_length
        //
        $data .= pack('nnn', $_packet->header->id, $this->error, $this->other_length);
        if ($this->other_length > 0)
        {
            $data .= pack('nN', 0, $this->other_data);
        }

        $_packet->offset += strlen($data);

        return $data;
    }

    /**
     * signs the given data with the given key, and returns the result
     *
     * @param string $_data      the data to sign
     * @param string $_key       key to use for signing
     * @param \NetDNS2\Data\Domain $_algorithm the algorithm to use; defaults to MD5
     *
     * @return string the signed digest
     * @throws \NetDNS2\Exception
     *
     */
    private function signHMAC(string $_data, ?string $_key = null, \NetDNS2\Data\Domain $_algorithm = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, self::HMAC_MD5)): string
    {
        //
        // use the hash extension; this is included by default in >= 5.1.2 which is our dependent version anyway- so it's easy to switch to it.
        //
        if (extension_loaded('hash') == true)
        {
            if (isset(self::$hash_algorithms[strval($_algorithm)]) == false)
            {
                throw new \NetDNS2\Exception('invalid or unsupported algorithm', \NetDNS2\ENUM\Error::PARSE_ERROR);
            }

            return hash_hmac(self::$hash_algorithms[strval($_algorithm)], $_data, $_key, true);
        }

        //
        // if the hash extension isn't loaded, and they selected something other than MD5, throw an exception
        //
        if ($_algorithm != self::HMAC_MD5)
        {
            throw new \NetDNS2\Exception('only HMAC-MD5 supported. please install the php-extension "hash" in order to use the sha-family',
                \NetDNS2\ENUM\Error::PARSE_ERROR);
        }

        //
        // otherwise, do it ourselves
        //
        if (is_null($_key) == true)
        {
            return pack('H*', md5($_data));
        }

        $_key = str_pad($_key, 64, chr(0x00));
        if (strlen($_key) > 64)
        {
            $_key = pack('H*', md5($_key));
        }

        $k_ipad = $_key ^ str_repeat(chr(0x36), 64);
        $k_opad = $_key ^ str_repeat(chr(0x5c), 64);

        return $this->signHMAC($k_opad . pack('H*', md5($k_ipad . $_data)), null, $_algorithm);
    }
}
