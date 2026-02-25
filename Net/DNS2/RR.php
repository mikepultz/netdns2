<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   Net_DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 */

/**
 * Abstract base class for DNS Resource Records (RFC1035 section 4.1.3)
 */
abstract class Net_DNS2_RR
{
    public string $name = '';
    public string $type = '';
    public string|int $class = 'IN';
    public int $ttl = 86400;
    public int|string $rdlength = 0;
    public string $rdata = '';

    abstract protected function rrToString(): string;
    abstract protected function rrFromString(array $rdata): bool;
    abstract protected function rrSet(Net_DNS2_Packet &$packet): bool;
    abstract protected function rrGet(Net_DNS2_Packet &$packet): ?string;

    /**
     * @throws Net_DNS2_Exception
     */
    public function __construct(?Net_DNS2_Packet &$packet = null, ?array $rr = null)
    {
        if ($packet !== null && $rr !== null) {
            if (!$this->set($packet, $rr)) {
                throw new Net_DNS2_Exception(
                    'failed to generate resource record',
                    Net_DNS2_Lookups::E_RR_INVALID
                );
            }
        } else {
            $class = Net_DNS2_Lookups::$rr_types_class_to_id[get_class($this)] ?? null;
            if ($class !== null) {
                $this->type = Net_DNS2_Lookups::$rr_types_by_id[$class];
            }

            $this->class = 'IN';
            $this->ttl   = 86400;
        }
    }

    public function __toString(): string
    {
        return "{$this->name}. {$this->ttl} {$this->class} {$this->type} {$this->rrToString()}";
    }

    /**
     * @return array<string, mixed>
     */
    public function asArray(): array
    {
        return [
            'name'  => $this->name,
            'ttl'   => $this->ttl,
            'class' => $this->class,
            'type'  => $this->type,
            'rdata' => $this->rrToString(),
        ];
    }

    protected function formatString(string $string): string
    {
        return '"' . str_replace('"', '\"', trim($string, '"')) . '"';
    }

    /**
     * @return array<string>
     */
    protected function buildString(array $chunks): array
    {
        $data = [];
        $c = 0;
        $in = false;

        foreach ($chunks as $r) {
            $r = trim($r);
            if ($r === '') {
                continue;
            }

            if ($r[0] === '"' && $r[strlen($r) - 1] === '"' && $r[strlen($r) - 2] !== '\\') {
                $data[$c] = $r;
                ++$c;
                $in = false;
            } elseif ($r[0] === '"') {
                $data[$c] = $r;
                $in = true;
            } elseif ($r[strlen($r) - 1] === '"' && $r[strlen($r) - 2] !== '\\') {
                $data[$c] .= ' ' . $r;
                ++$c;
                $in = false;
            } else {
                if ($in) {
                    $data[$c] .= ' ' . $r;
                } else {
                    $data[$c++] = $r;
                }
            }
        }

        foreach ($data as $index => $string) {
            $data[$index] = str_replace('\"', '"', trim($string, '"'));
        }

        return $data;
    }

    /**
     * @throws Net_DNS2_Exception
     */
    public function set(Net_DNS2_Packet &$packet, array $rr): bool
    {
        $this->name = $rr['name'];
        $this->type = Net_DNS2_Lookups::$rr_types_by_id[$rr['type']];

        $this->class = ($this->type === 'OPT')
            ? $rr['class']
            : Net_DNS2_Lookups::$classes_by_id[$rr['class']];

        $this->ttl      = $rr['ttl'];
        $this->rdlength = $rr['rdlength'];
        $this->rdata    = substr($packet->rdata, $packet->offset, $rr['rdlength']);

        return $this->rrSet($packet);
    }

    /**
     * @throws Net_DNS2_Exception
     */
    public function get(Net_DNS2_Packet &$packet): string
    {
        $rdata = '';

        $data = $packet->compress($this->name, $packet->offset);

        if ($this->type === 'OPT') {
            $this->preBuild();
            $data .= pack(
                'nnN',
                Net_DNS2_Lookups::$rr_types_by_name[$this->type],
                $this->class,
                $this->ttl
            );
        } else {
            $data .= pack(
                'nnN',
                Net_DNS2_Lookups::$rr_types_by_name[$this->type],
                Net_DNS2_Lookups::$classes_by_name[$this->class],
                $this->ttl
            );
        }

        $packet->offset += 10;

        if ($this->rdlength !== -1) {
            $rdata = $this->rrGet($packet);
        }

        $data .= pack('n', strlen((string)$rdata)) . $rdata;

        return $data;
    }

    /**
     * @throws Net_DNS2_Exception
     */
    public static function parse(Net_DNS2_Packet &$packet): ?self
    {
        $object = [];

        $object['name'] = $packet->expand($packet, $packet->offset);
        if ($object['name'] === null) {
            throw new Net_DNS2_Exception(
                'failed to parse resource record: failed to expand name.',
                Net_DNS2_Lookups::E_PARSE_ERROR
            );
        }
        if ($packet->rdlength < ($packet->offset + 10)) {
            throw new Net_DNS2_Exception(
                'failed to parse resource record: packet too small.',
                Net_DNS2_Lookups::E_PARSE_ERROR
            );
        }

        $object['type']     = ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);
        $object['class']    = ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);
        $object['ttl']      = ord($packet->rdata[$packet->offset++]) << 24 |
                              ord($packet->rdata[$packet->offset++]) << 16 |
                              ord($packet->rdata[$packet->offset++]) << 8 |
                              ord($packet->rdata[$packet->offset++]);
        $object['rdlength'] = ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);

        if ($packet->rdlength < ($packet->offset + $object['rdlength'])) {
            return null;
        }

        $class = Net_DNS2_Lookups::$rr_types_id_to_class[$object['type']] ?? null;

        if ($class !== null) {
            $o = new $class($packet, $object);
            if ($o) {
                $packet->offset += $object['rdlength'];
            }
        } else {
            throw new Net_DNS2_Exception(
                'un-implemented resource record type: ' . $object['type'],
                Net_DNS2_Lookups::E_RR_INVALID
            );
        }

        return $o;
    }

    public function cleanString(string $data): string
    {
        return strtolower(rtrim($data, '.'));
    }

    /**
     * @throws Net_DNS2_Exception
     */
    public static function fromString(string $line): static
    {
        if ($line === '') {
            throw new Net_DNS2_Exception(
                'empty config line provided.',
                Net_DNS2_Lookups::E_PARSE_ERROR
            );
        }

        $class = 'IN';
        $ttl   = 86400;

        $values = preg_split('/[\s]+/', $line);
        if (count($values) < 3) {
            throw new Net_DNS2_Exception(
                'failed to parse config: minimum of name, type and rdata required.',
                Net_DNS2_Lookups::E_PARSE_ERROR
            );
        }

        $name = trim(strtolower(array_shift($values)), '.');

        foreach ($values as $value) {
            switch (true) {
                case is_numeric($value):
                case $value === 0:
                    $ttl = array_shift($values);
                    break;

                case isset(Net_DNS2_Lookups::$classes_by_name[strtoupper($value)]):
                    $class = strtoupper(array_shift($values));
                    break;

                case isset(Net_DNS2_Lookups::$rr_types_by_name[strtoupper($value)]):
                    $type = strtoupper(array_shift($values));
                    break 2;

                default:
                    throw new Net_DNS2_Exception(
                        "invalid config line provided: unknown file: {$value}",
                        Net_DNS2_Lookups::E_PARSE_ERROR
                    );
            }
        }

        $class_name = Net_DNS2_Lookups::$rr_types_id_to_class[
            Net_DNS2_Lookups::$rr_types_by_name[$type]
        ] ?? null;

        if ($class_name === null) {
            throw new Net_DNS2_Exception(
                "un-implemented resource record type: {$type}",
                Net_DNS2_Lookups::E_RR_INVALID
            );
        }

        $o = new $class_name();
        $o->name  = $name;
        $o->class = $class;
        $o->ttl   = (int)$ttl;

        if ($o->rrFromString($values) === false) {
            throw new Net_DNS2_Exception(
                "failed to parse rdata for config: {$line}",
                Net_DNS2_Lookups::E_PARSE_ERROR
            );
        }

        return $o;
    }
}
