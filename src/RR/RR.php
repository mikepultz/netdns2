<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\Lookups;
use Net\DNS2\Exception;
use Net\DNS2\Packet\Packet;

/**
 * Abstract base class for DNS Resource Records (RFC1035 section 4.1.3)
 */
abstract class RR
{
    public string $name = '';
    public string $type = '';
    public string|int $class = 'IN';
    public int $ttl = 86400;
    public int|string $rdlength = 0;
    public string $rdata = '';

    abstract protected function rrToString(): string;
    abstract protected function rrFromString(array $rdata): bool;
    abstract protected function rrSet(Packet &$packet): bool;
    abstract protected function rrGet(Packet &$packet): ?string;

    /**
     * @throws Exception
     */
    public function __construct(?Packet &$packet = null, ?array $rr = null)
    {
        if ($packet !== null && $rr !== null) {
            if (!$this->set($packet, $rr)) {
                throw new Exception(
                    'failed to generate resource record',
                    Lookups::E_RR_INVALID
                );
            }
        } else {
            $class = Lookups::$rr_types_class_to_id[get_class($this)] ?? null;
            if ($class !== null) {
                $this->type = Lookups::$rr_types_by_id[$class];
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
     * @throws Exception
     */
    public function set(Packet &$packet, array $rr): bool
    {
        $this->name = $rr['name'];
        $this->type = Lookups::$rr_types_by_id[$rr['type']];

        $this->class = ($this->type === 'OPT')
            ? $rr['class']
            : Lookups::$classes_by_id[$rr['class']];

        $this->ttl      = $rr['ttl'];
        $this->rdlength = $rr['rdlength'];
        $this->rdata    = substr($packet->rdata, $packet->offset, $rr['rdlength']);

        return $this->rrSet($packet);
    }

    /**
     * @throws Exception
     */
    public function get(Packet &$packet): string
    {
        $rdata = '';

        $data = $packet->compress($this->name, $packet->offset);

        if ($this->type === 'OPT') {
            $this->preBuild();
            $data .= pack(
                'nnN',
                Lookups::$rr_types_by_name[$this->type],
                $this->class,
                $this->ttl
            );
        } else {
            $data .= pack(
                'nnN',
                Lookups::$rr_types_by_name[$this->type],
                Lookups::$classes_by_name[$this->class],
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
     * @throws Exception
     */
    public static function parse(Packet &$packet): ?self
    {
        $object = [];

        $object['name'] = $packet->expand($packet, $packet->offset);
        if ($object['name'] === null) {
            throw new Exception(
                'failed to parse resource record: failed to expand name.',
                Lookups::E_PARSE_ERROR
            );
        }
        if ($packet->rdlength < ($packet->offset + 10)) {
            throw new Exception(
                'failed to parse resource record: packet too small.',
                Lookups::E_PARSE_ERROR
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

        $class = Lookups::$rr_types_id_to_class[$object['type']] ?? null;

        if ($class !== null) {
            $o = new $class($packet, $object);
            if ($o) {
                $packet->offset += $object['rdlength'];
            }
        } else {
            throw new Exception(
                'un-implemented resource record type: ' . $object['type'],
                Lookups::E_RR_INVALID
            );
        }

        return $o;
    }

    public function cleanString(string $data): string
    {
        return strtolower(rtrim($data, '.'));
    }

    /**
     * @throws Exception
     */
    public static function fromString(string $line): static
    {
        if ($line === '') {
            throw new Exception(
                'empty config line provided.',
                Lookups::E_PARSE_ERROR
            );
        }

        $class = 'IN';
        $ttl   = 86400;

        $values = preg_split('/[\s]+/', $line);
        if (count($values) < 3) {
            throw new Exception(
                'failed to parse config: minimum of name, type and rdata required.',
                Lookups::E_PARSE_ERROR
            );
        }

        $name = trim(strtolower(array_shift($values)), '.');

        foreach ($values as $value) {
            switch (true) {
                case is_numeric($value):
                case $value === 0:
                    $ttl = array_shift($values);
                    break;

                case isset(Lookups::$classes_by_name[strtoupper($value)]):
                    $class = strtoupper(array_shift($values));
                    break;

                case isset(Lookups::$rr_types_by_name[strtoupper($value)]):
                    $type = strtoupper(array_shift($values));
                    break 2;

                default:
                    throw new Exception(
                        "invalid config line provided: unknown file: {$value}",
                        Lookups::E_PARSE_ERROR
                    );
            }
        }

        $class_name = Lookups::$rr_types_id_to_class[
            Lookups::$rr_types_by_name[$type]
        ] ?? null;

        if ($class_name === null) {
            throw new Exception(
                "un-implemented resource record type: {$type}",
                Lookups::E_RR_INVALID
            );
        }

        $o = new $class_name();
        $o->name  = $name;
        $o->class = $class;
        $o->ttl   = (int)$ttl;

        if ($o->rrFromString($values) === false) {
            throw new Exception(
                "failed to parse rdata for config: {$line}",
                Lookups::E_PARSE_ERROR
            );
        }

        return $o;
    }
}
