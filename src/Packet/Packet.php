<?php declare(strict_types=1);

namespace Net\DNS2\Packet;

use Net\DNS2\DNS2;
use Net\DNS2\Exception;
use Net\DNS2\Header;
use Net\DNS2\Question;
use Net\DNS2\RR\RR;

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
 * Base DNS packet class (extended by Request and Response)
 */
class Packet
{
    public string $rdata = '';
    public int $rdlength = 0;
    public int $offset = 0;
    public ?Header $header = null;

    /** @var array<Question> */
    public array $question = [];

    /** @var array<RR> */
    public array $answer = [];

    /** @var array<RR> */
    public array $authority = [];

    /** @var array<RR> */
    public array $additional = [];

    /** @var array<string, int> */
    private array $compressed = [];

    public function __toString(): string
    {
        $output = $this->header->__toString();

        foreach ($this->question as $x) {
            $output .= $x->__toString() . "\n";
        }
        foreach ($this->answer as $x) {
            $output .= $x->__toString() . "\n";
        }
        foreach ($this->authority as $x) {
            $output .= $x->__toString() . "\n";
        }
        foreach ($this->additional as $x) {
            $output .= $x->__toString() . "\n";
        }

        return $output;
    }

    /**
     * @throws Exception
     */
    public function get(): string
    {
        $data = $this->header->get($this);

        foreach ($this->question as $x) {
            $data .= $x->get($this);
        }
        foreach ($this->answer as $x) {
            $data .= $x->get($this);
        }
        foreach ($this->authority as $x) {
            $data .= $x->get($this);
        }
        foreach ($this->additional as $x) {
            $data .= $x->get($this);
        }

        return $data;
    }

    public function compress(string $name, int &$offset): string
    {
        $names    = str_replace('\.', '.', preg_split('/(?<!\\\)\./', $name));
        $compname = '';

        while (!empty($names)) {
            $dname = implode('.', $names);

            if (isset($this->compressed[$dname])) {
                $compname .= pack('n', 0xc000 | $this->compressed[$dname]);
                $offset += 2;
                break;
            }

            $this->compressed[$dname] = $offset;

            $first  = array_shift($names);
            $length = strlen($first);
            if ($length <= 0) {
                continue;
            }

            if ($length > 63) {
                $length = 63;
                $first  = substr($first, 0, $length);
            }

            $compname .= pack('Ca*', $length, $first);
            $offset += $length + 1;
        }

        if (empty($names)) {
            $compname .= pack('C', 0);
            $offset++;
        }

        return $compname;
    }

    public static function pack(string $name): string
    {
        $names    = explode('.', $name);
        $compname = '';

        while (!empty($names)) {
            $first  = array_shift($names);
            $length = strlen($first);

            $compname .= pack('Ca*', $length, $first);
        }

        $compname .= "\0";

        return $compname;
    }

    public static function expand(
        Packet &$packet,
        int &$offset,
        bool $escape_dot_literals = false,
    ): ?string {
        $name = '';

        while (true) {
            if ($packet->rdlength < ($offset + 1)) {
                return null;
            }

            $xlen = ord($packet->rdata[$offset]);
            if ($xlen === 0) {
                ++$offset;
                break;
            } elseif (($xlen & 0xc0) === 0xc0) {
                if ($packet->rdlength < ($offset + 2)) {
                    return null;
                }

                $ptr = (ord($packet->rdata[$offset]) << 8 | ord($packet->rdata[$offset + 1])) & 0x3fff;
                $name2 = self::expand($packet, $ptr);
                if ($name2 === null) {
                    return null;
                }

                $name .= $name2;
                $offset += 2;
                break;
            } else {
                ++$offset;

                if ($packet->rdlength < ($offset + $xlen)) {
                    return null;
                }

                $elem = substr($packet->rdata, $offset, $xlen);

                if ($escape_dot_literals && str_contains($elem, '.')) {
                    $elem = str_replace('.', '\.', $elem);
                }

                $name .= $elem . '.';
                $offset += $xlen;
            }
        }

        return trim($name, '.');
    }

    public static function label(Packet &$packet, int &$offset): ?string
    {
        if ($packet->rdlength < ($offset + 1)) {
            return null;
        }

        $xlen = ord($packet->rdata[$offset]);
        ++$offset;

        if (($xlen + $offset) > $packet->rdlength) {
            $name = substr($packet->rdata, $offset);
            $offset = $packet->rdlength;
        } else {
            $name = substr($packet->rdata, $offset, $xlen);
            $offset += $xlen;
        }

        return $name;
    }

    public function copy(Packet $packet): bool
    {
        $this->header     = $packet->header;
        $this->question   = $packet->question;
        $this->answer     = $packet->answer;
        $this->authority  = $packet->authority;
        $this->additional = $packet->additional;

        return true;
    }

    public function reset(): bool
    {
        $this->header->id  = $this->header->nextPacketId();
        $this->rdata       = '';
        $this->rdlength    = 0;
        $this->offset      = 0;
        $this->answer      = [];
        $this->authority   = [];
        $this->additional  = [];
        $this->compressed  = [];

        return true;
    }
}
