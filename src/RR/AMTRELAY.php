<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\DNS2;
use Net\DNS2\Packet\Packet;

/**
 * AMTRELAY Resource Record - RFC8777 section 4.2
 */
class AMTRELAY extends RR
{
    const AMTRELAY_TYPE_NONE    = 0;
    const AMTRELAY_TYPE_IPV4    = 1;
    const AMTRELAY_TYPE_IPV6    = 2;
    const AMTRELAY_TYPE_DOMAIN  = 3;

    public int $precedence = 0;
    public int $discovery = 0;
    public int $relay_type = 0;
    public string $relay = '';

    #[\Override]
    protected function rrToString(): string
    {
        $out = $this->precedence . ' ' . $this->discovery . ' ' . $this->relay_type . ' ' . $this->relay;

        if (($this->relay_type === self::AMTRELAY_TYPE_NONE) || ($this->relay_type === self::AMTRELAY_TYPE_DOMAIN)) {
            $out .= '.';
        }

        return $out;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->precedence   = (int) array_shift($rdata);
        $this->discovery    = (int) array_shift($rdata);
        $this->relay_type   = (int) array_shift($rdata);
        $this->relay        = trim(strtolower(trim(array_shift($rdata))), '.');

        if ($this->discovery !== 0) {
            $this->discovery = 1;
        }

        switch ($this->relay_type) {
            case self::AMTRELAY_TYPE_NONE:
                $this->relay = '';
                break;

            case self::AMTRELAY_TYPE_IPV4:
                if (DNS2::isIPv4($this->relay) === false) {
                    return false;
                }
                break;

            case self::AMTRELAY_TYPE_IPV6:
                if (DNS2::isIPv6($this->relay) === false) {
                    return false;
                }
                break;

            case self::AMTRELAY_TYPE_DOMAIN:
                break;

            default:
                return false;
        }

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('Cprecedence/Csecond', $this->rdata);

            $this->precedence   = $x['precedence'];
            $this->discovery    = ($x['second'] >> 7) & 0x1;
            $this->relay_type   = $x['second'] & 0xf;

            $offset = 2;

            switch ($this->relay_type) {
                case self::AMTRELAY_TYPE_NONE:
                    $this->relay = '';
                    break;

                case self::AMTRELAY_TYPE_IPV4:
                    $this->relay = inet_ntop(substr($this->rdata, $offset, 4));
                    break;

                case self::AMTRELAY_TYPE_IPV6:
                    $ip = unpack('n8', substr($this->rdata, $offset, 16));
                    if (count($ip) === 8) {
                        $this->relay = vsprintf('%x:%x:%x:%x:%x:%x:%x:%x', $ip);
                    } else {
                        return false;
                    }
                    break;

                case self::AMTRELAY_TYPE_DOMAIN:
                    $doffset = $packet->offset + $offset;
                    $this->relay = Packet::label($packet, $doffset);
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
        $data = pack('CC', $this->precedence, ($this->discovery << 7) | $this->relay_type);

        switch ($this->relay_type) {
            case self::AMTRELAY_TYPE_NONE:
                break;

            case self::AMTRELAY_TYPE_IPV4:
            case self::AMTRELAY_TYPE_IPV6:
                $data .= inet_pton($this->relay);
                break;

            case self::AMTRELAY_TYPE_DOMAIN:
                $data .= pack('Ca*', strlen($this->relay), $this->relay);
                break;

            default:
                return null;
        }

        $packet->offset += strlen($data);

        return $data;
    }
}
