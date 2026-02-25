<?php declare(strict_types=1);

namespace Net\DNS2\RR;


use Net\DNS2\Resolver;
use Net\DNS2\DNS2;
use Net\DNS2\Packet\Packet;

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
 */
class TKEY extends RR
{
    public string $algorithm = '';
    public int $inception = 0;
    public int $expiration = 0;
    public int $mode = 0;
    public int $error = 0;
    public int $key_size = 0;
    public string $key_data = '';
    public int $other_size = 0;
    public string $other_data = '';

    const TSIG_MODE_RES         = 0;
    const TSIG_MODE_SERV_ASSIGN = 1;
    const TSIG_MODE_DH          = 2;
    const TSIG_MODE_GSS_API     = 3;
    const TSIG_MODE_RESV_ASSIGN = 4;
    const TSIG_MODE_KEY_DELE    = 5;

    /** @var array<int, string> */
    public array $tsgi_mode_id_to_name = [
        self::TSIG_MODE_RES         => 'Reserved',
        self::TSIG_MODE_SERV_ASSIGN => 'Server Assignment',
        self::TSIG_MODE_DH          => 'Diffie-Hellman',
        self::TSIG_MODE_GSS_API     => 'GSS-API',
        self::TSIG_MODE_RESV_ASSIGN => 'Resolver Assignment',
        self::TSIG_MODE_KEY_DELE    => 'Key Deletion',
    ];

    #[\Override]
    protected function rrToString(): string
    {
        $out = $this->cleanString($this->algorithm) . '. ' . $this->mode;
        if ($this->key_size > 0) {
            $out .= ' ' . trim($this->key_data, '.') . '.';
        } else {
            $out .= ' .';
        }

        return $out;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->algorithm  = $this->cleanString(array_shift($rdata));
        $this->mode       = (int)array_shift($rdata);
        $this->key_data   = trim(array_shift($rdata), '.');

        $this->inception  = time();
        $this->expiration = time() + 86400;
        $this->error      = 0;
        $this->key_size   = strlen($this->key_data);
        $this->other_size = 0;
        $this->other_data = '';

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {

            $offset = $packet->offset;
            $this->algorithm = Packet::expand($packet, $offset);

            $x = unpack(
                '@' . $offset . '/Ninception/Nexpiration/nmode/nerror/nkey_size',
                $packet->rdata
            );

            $this->inception  = DNS2::expandUint32($x['inception']);
            $this->expiration = DNS2::expandUint32($x['expiration']);
            $this->mode       = $x['mode'];
            $this->error      = $x['error'];
            $this->key_size   = $x['key_size'];

            $offset += 14;

            if ($this->key_size > 0) {
                $this->key_data = substr($packet->rdata, $offset, $this->key_size);
                $offset += $this->key_size;
            }

            $x = unpack('@' . $offset . '/nother_size', $packet->rdata);

            $this->other_size = $x['other_size'];
            $offset += 2;

            if ($this->other_size > 0) {
                $this->other_data = substr(
                    $packet->rdata, $offset, $this->other_size
                );
            }

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->algorithm) > 0) {

            $this->key_size   = strlen($this->key_data);
            $this->other_size = strlen($this->other_data);

            $data = Packet::pack($this->algorithm);

            $data .= pack(
                'NNnnn', $this->inception, $this->expiration,
                $this->mode, 0, $this->key_size
            );

            if ($this->key_size > 0) {
                $data .= $this->key_data;
            }

            $data .= pack('n', $this->other_size);
            if ($this->other_size > 0) {
                $data .= $this->other_data;
            }

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
