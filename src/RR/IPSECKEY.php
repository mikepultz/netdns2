<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\DNS2;
use Net\DNS2\Packet\Packet;

/**
 * IPSECKEY Resource Record - RFC4025 section 2.1
 *
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |  precedence   | gateway type  |  algorithm  |     gateway     |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------+                 +
 *     ~                            gateway                            ~
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                                                               /
 *     /                          public key                           /
 *     /                                                               /
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
 */
class IPSECKEY extends RR
{
    const GATEWAY_TYPE_NONE   = 0;
    const GATEWAY_TYPE_IPV4   = 1;
    const GATEWAY_TYPE_IPV6   = 2;
    const GATEWAY_TYPE_DOMAIN = 3;

    const ALGORITHM_NONE = 0;
    const ALGORITHM_DSA  = 1;
    const ALGORITHM_RSA  = 2;

    public int $precedence = 0;
    public int $gateway_type = 0;
    public int $algorithm = 0;
    public string $gateway = '';
    public string $key = '';

    #[\Override]
    protected function rrToString(): string
    {
        $out = $this->precedence . ' ' . $this->gateway_type . ' ' .
            $this->algorithm . ' ';

        switch ($this->gateway_type) {
        case self::GATEWAY_TYPE_NONE:
            $out .= '. ';
            break;

        case self::GATEWAY_TYPE_IPV4:
        case self::GATEWAY_TYPE_IPV6:
            $out .= $this->gateway . ' ';
            break;

        case self::GATEWAY_TYPE_DOMAIN:
            $out .= $this->gateway . '. ';
            break;
        }

        $out .= $this->key;
        return $out;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $precedence   = (int) array_shift($rdata);
        $gateway_type = (int) array_shift($rdata);
        $algorithm    = (int) array_shift($rdata);
        $gateway      = trim(strtolower(trim(array_shift($rdata))), '.');
        $key          = array_shift($rdata);

        switch ($gateway_type) {
        case self::GATEWAY_TYPE_NONE:
            $gateway = '';
            break;

        case self::GATEWAY_TYPE_IPV4:
            if (DNS2::isIPv4($gateway) === false) {
                return false;
            }
            break;

        case self::GATEWAY_TYPE_IPV6:
            if (DNS2::isIPv6($gateway) === false) {
                return false;
            }
            break;

        case self::GATEWAY_TYPE_DOMAIN:
            break;

        default:
            return false;
        }

        switch ($algorithm) {
        case self::ALGORITHM_NONE:
            $key = '';
            break;

        case self::ALGORITHM_DSA:
        case self::ALGORITHM_RSA:
            break;

        default:
            return false;
        }

        $this->precedence   = $precedence;
        $this->gateway_type = $gateway_type;
        $this->algorithm    = $algorithm;
        $this->gateway      = $gateway;
        $this->key          = $key;

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('Cprecedence/Cgateway_type/Calgorithm', $this->rdata);

            $this->precedence   = $x['precedence'];
            $this->gateway_type = $x['gateway_type'];
            $this->algorithm    = $x['algorithm'];

            $offset = 3;

            switch ($this->gateway_type) {
            case self::GATEWAY_TYPE_NONE:
                $this->gateway = '';
                break;

            case self::GATEWAY_TYPE_IPV4:
                $this->gateway = inet_ntop(substr($this->rdata, $offset, 4));
                $offset += 4;
                break;

            case self::GATEWAY_TYPE_IPV6:
                $ip = unpack('n8', substr($this->rdata, $offset, 16));
                if (count($ip) === 8) {
                    $this->gateway = vsprintf('%x:%x:%x:%x:%x:%x:%x:%x', $ip);
                    $offset += 16;
                } else {
                    return false;
                }
                break;

            case self::GATEWAY_TYPE_DOMAIN:
                $doffset = $offset + $packet->offset;
                $this->gateway = Packet::expand($packet, $doffset);
                $offset = ($doffset - $packet->offset);
                break;

            default:
                return false;
            }

            switch ($this->algorithm) {
            case self::ALGORITHM_NONE:
                $this->key = '';
                break;

            case self::ALGORITHM_DSA:
            case self::ALGORITHM_RSA:
                $this->key = base64_encode(substr($this->rdata, $offset));
                break;

            default:
                return false;
            }

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        $data = pack(
            'CCC', $this->precedence, $this->gateway_type, $this->algorithm
        );

        switch ($this->gateway_type) {
        case self::GATEWAY_TYPE_NONE:
            break;

        case self::GATEWAY_TYPE_IPV4:
        case self::GATEWAY_TYPE_IPV6:
            $data .= inet_pton($this->gateway);
            break;

        case self::GATEWAY_TYPE_DOMAIN:
            $data .= chr(strlen($this->gateway)) . $this->gateway;
            break;

        default:
            return null;
        }

        switch ($this->algorithm) {
        case self::ALGORITHM_NONE:
            break;

        case self::ALGORITHM_DSA:
        case self::ALGORITHM_RSA:
            $data .= base64_decode($this->key);
            break;

        default:
            return null;
        }

        $packet->offset += strlen($data);

        return $data;
    }
}
