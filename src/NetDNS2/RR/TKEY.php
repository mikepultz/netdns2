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
 * TKEY Resource Record - RFC 2930 section 2
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   ALGORITHM                   / 
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   INCEPTION                   |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   EXPIRATION                  |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   MODE                        |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   ERROR                       |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   KEY SIZE                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   KEY DATA                    /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   OTHER SIZE                  |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    /                   OTHER DATA                  /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
final class TKEY extends \NetDNS2\RR
{
    /*
     * TSIG Modes
     */
    public const TSIG_MODE_RES           = 0;
    public const TSIG_MODE_SERV_ASSIGN   = 1;
    public const TSIG_MODE_DH            = 2;
    public const TSIG_MODE_GSS_API       = 3;
    public const TSIG_MODE_RESV_ASSIGN   = 4;
    public const TSIG_MODE_KEY_DELE      = 5;

    /**
     * map the mod id's to names so we can validate
     *
     * @var array<int,string>
     */
    public static array $tsgi_mode_id_to_name = [

        self::TSIG_MODE_RES           => 'Reserved',
        self::TSIG_MODE_SERV_ASSIGN   => 'Server Assignment',
        self::TSIG_MODE_DH            => 'Diffie-Hellman',
        self::TSIG_MODE_GSS_API       => 'GSS-API',
        self::TSIG_MODE_RESV_ASSIGN   => 'Resolver Assignment',
        self::TSIG_MODE_KEY_DELE      => 'Key Deletion'
    ];

    /*
     * algorithm name
     */
    protected \NetDNS2\Data\Domain $algorithm;

    /*
     * The inception time and expiration times are in number of seconds since the beginning of 1 January 1970 GMT 
     * ignoring leap seconds
     */
    protected string $inception;
    protected string $expiration;

    /*
     * The mode field specifies the general scheme for key agreement or the purpose of the TKEY DNS message.
     */
    protected int $mode;

    /*
     * The error code field is an extended RCODE.
     */
    protected int $error;

    /*
     * The key data size field is an unsigned 16 bit integer in network order which specifies the size of the key 
     * exchange data field in octets.
     */
    protected int $key_size;
    protected string $key_data;

    /*
     * The Other Size and Other Data fields are not used in this specification but may be used in future extensions.
     */
    protected int $other_size;
    protected string $other_data;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        $out = $this->algorithm . '. ' . $this->mode;

        if ($this->key_size > 0)
        {
            $out .= ' ' . trim($this->key_data, '.') . '.';
        } else
        {
            $out .= ' .';
        }

        return $out;
    }

    /**
     * data passed in is assumed: <algorithm> <mode> <key>
     *
     *
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     * @throws \NetDNS2\Exception
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->algorithm  = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, array_shift($_rdata));

        //
        // check the mode value
        //
        $mode = intval($this->sanitize(array_shift($_rdata)));

        if (isset(self::$tsgi_mode_id_to_name[$mode]) == false)
        {
            throw new \NetDNS2\Exception('unsupported TKEY mode value: ' . $mode, \NetDNS2\ENUM\Error::PARSE_ERROR);
        } else
        {
            $this->mode = $mode;
        }

        $this->key_data = $this->sanitize(array_shift($_rdata));

        //
        // the rest of the data is set manually
        //
        $this->inception  = strval(time());
        $this->expiration = strval(time() + 86400); // 1 day
        $this->error      = 0;
        $this->key_size   = strlen($this->key_data);
        $this->other_size = 0;
        $this->other_data = '';

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

        $offset = $_packet->offset;

        $this->algorithm = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, $_packet->rdata, $offset);
            
        //
        // unpack inception, expiration, mode, error and key size
        //
        $val = unpack('Na/Nb/nc/nd/ne', $_packet->rdata, $offset);
        if ($val === false)
        {
            return false;
        }

        list('a' => $i, 'b' => $e, 'c' => $this->mode, 'd' => $this->error, 'e' => $this->key_size) = (array)$val;

        $this->inception  = \NetDNS2\Client::expandUint32($i);
        $this->expiration = \NetDNS2\Client::expandUint32($e);

        $offset += 14;

        //
        // if key_size > 0, then copy out the key
        //
        if ($this->key_size > 0)
        {
            $this->key_data = substr($_packet->rdata, $offset, $this->key_size);
            $offset += $this->key_size;
        }

        //
        // unpack the other length
        //
        $val = unpack('nx', $_packet->rdata, $offset);
        if ($val === false)
        {
            return false;
        }
        
        list('x' => $this->other_size) = (array)$val;
        $offset += 2;

        //
        // if other_size > 0, then copy out the data
        //
        if ($this->other_size > 0)
        {
            $this->other_data = substr($_packet->rdata, $offset, $this->other_size);
        }

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if ($this->algorithm->length() == 0)
        {
            return '';
        }
            
        //
        // make sure the size values are correct
        //
        $this->key_size   = strlen($this->key_data);
        $this->other_size = strlen($this->other_data);

        //
        // pack in the inception, expiration, mode, error and key size
        //
        $data = $this->algorithm->encode($_packet->offset) . pack('NNnnn', $this->inception, $this->expiration, $this->mode, 0, $this->key_size);

        //
        // if the key_size > 0, then add the key
        //
        if ($this->key_size > 0)
        {
            $data .= $this->key_data;
        }

        //
        // pack in the other size
        //
        $data .= pack('n', $this->other_size);

        if ($this->other_size > 0)
        {
            $data .= $this->other_data;
        }

        $_packet->offset += 16 + $this->key_size + $this->other_size;

        return $data;
    }
}
