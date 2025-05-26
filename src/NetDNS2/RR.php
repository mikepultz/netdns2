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

namespace NetDNS2;

/**
 * This is the base class for DNS Resource Records
 *
 * Each resource record type (defined in RR/*.php) extends this class for base functionality.
 *
 * This class handles parsing and constructing the common parts of the DNS resource records, while the RR specific functionality is handled in each 
 * child class.
 *
 * DNS resource record format - RFC1035 section 4.1.3
 *
 *      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                                               |
 *    /                                               /
 *    /                      NAME                     /
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                      TYPE                     |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                     CLASS                     |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                      TTL                      |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   RDLENGTH                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 *    /                     RDATA                     /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
abstract class RR implements \Stringable
{
    /**
     * The name of the resource record
     */
    public \NetDNS2\Data\Domain $name;

    /**
     * The resource record type
     */
    public \NetDNS2\ENUM\RRType $type;

    /**
     * The resouce record class
     */
    public \NetDNS2\ENUM\RRClass $class;

    /**
     * The UDP length used instead of the class value for OPT records
     */
    public int $udp_length;

    /**
     * The time to live for this resource record
     */
    public int $ttl;

    /**
     * The length of the rdata field
     */
    public int $rdlength = 0;

    /**
     * The resource record specific data as a packed binary string
     */
    public string $rdata = '';

    /**
     * abstract definition - method to return a RR as a string; not to be confused with the __toString() magic method.
     *
     */
    abstract protected function rrToString(): string;

    /**
     * abstract definition - parses a RR from a standard DNS config line
     *
     * @param array<string> $_rdata a string split line of values for the rdata
     *
     */
    abstract protected function rrFromString(array $_rdata): bool;

    /**
     * abstract definition - sets a \NetDNS2\RR from a \NetDNS2\Packet object
     *
     * @param \NetDNS2\Packet &$_packet a \NetDNS2\Packet packet to parse the RR from
     *
     */
    abstract protected function rrSet(\NetDNS2\Packet &$_packet): bool;

    /**
     * abstract definition - returns a binary packet DNS RR object
     *
     * @param \NetDNS2\Packet &$_packet a \NetDNS2\Packet packet
     *
     * @return string                   either returns a binary packed string or empty string on failure
     *
     */
    abstract protected function rrGet(\NetDNS2\Packet &$_packet): string;

    /**
     * Constructor - builds a new \NetDNS2\RR object
     *
     * @param \NetDNS2\Packet     &$_packet a \NetDNS2\Packet packet or null to create an empty object
     * @param array<string,mixed> $_rr      an array with RR parse values or null to create an empty object
     *
     * @throws \NetDNS2\Exception
     *
     */
    public function __construct(?\NetDNS2\Packet &$_packet = null, ?array $_rr = null)
    {
        if ( (is_null($_packet) == false) && (is_null($_rr) == false) )
        {
            if ($this->set($_packet, $_rr) == false)
            {
                throw new \NetDNS2\Exception('failed to generate resource record', \NetDNS2\ENUM\Error::RR_INVALID);
            }

        } else
        {
            $this->type  = \NetDNS2\ENUM\RRType::set(str_replace('NetDNS2\\RR\\', '', get_class($this)));
            $this->class = \NetDNS2\ENUM\RRClass::set('IN');
            $this->ttl   = 86400;
        }
    }

    /**
     * magic method to handle setting values inside the individual \NetDNS2\RR objects
     *
     * @throws \NetDNS2\Exception
     *
     */
    public function __set(string $_name, mixed $_value): void 
    {
        if (property_exists(get_called_class(), $_name) == false)
        {
            throw new \NetDNS2\Exception('undefined property: ' . $_name, \NetDNS2\ENUM\Error::RR_INVALID);
        }

        //
        // use reflection to look for custom internal types
        //
        $property = new \ReflectionProperty(get_called_class(), $_name);

        //
        // get the type, and make sure it's a instance of a "ReflectionNamedType"; the union and intersection types don't have a getName() function call.
        //
        $type = $property->getType();

        if (($type instanceof \ReflectionNamedType) == false)
        {
            throw new \NetDNS2\Exception('property is not accessible via Reflection: ' . $_name, \NetDNS2\ENUM\Error::RR_INVALID);
        }

        switch($type->getName())
        {
            case 'NetDNS2\Data\Domain':
            {
                $this->$_name = new \NetDNS2\Data\Domain($_value);
            }
            break;
            case 'NetDNS2\Data\Mailbox':
            {
                $this->$_name = new \NetDNS2\Data\Mailbox($_value);
            }
            break;
            case '\NetDNS2\Data\Text':
            {
                $this->$_name = new \NetDNS2\Data\Text($_value);
            }
            break;
            default:
            {
                $this->$_name = $_value;
            }
        }
    }

    /**
     * magic method to return values from \NetDNS2\RR objects
     *
     * @throws \NetDNS2\Exception
     *
     */
    public function __get(string $_name): mixed 
    {
        if (property_exists(get_called_class(), $_name) == false)
        {
            throw new \NetDNS2\Exception('undefined property: ' . $_name, \NetDNS2\ENUM\Error::RR_INVALID);
        }

        return $this->$_name;
    }

    /**
     * magic __toString() method to return the \NetDNS2\RR object object as a string
     *
     */
    public function __toString(): string
    {
        return strval($this->name) . '. ' . $this->ttl . ' ' . $this->class->label() . ' ' . $this->type->label() . ' ' . $this->rrToString();
    }

    /**
     * return the same data as __toString(), but as an array, so each value can be used without having to parse the string.
     *
     * @return array<string,mixed>
     *
     */
    public function asArray(): array
    {
        return [

            'name'  => strval($this->name),
            'ttl'   => $this->ttl,
            'class' => $this->class->value,
            'type'  => $this->type->value,
            'rdata' => $this->rrToString()
        ];
    }

    /**
     * return a formatted string; if a string has spaces in it, then return it with double quotes around it, otherwise, return it as it was passed in.
     *
     * @param string $_string the string to format
     *
     */
    public static function formatString(string $_string): string
    {
        return '"' . str_replace('"', '\"', trim($_string, '"')) . '"';
    }
    
    /**
     * builds an array of strings from an array of chunks of text split by spaces
     *
     * @param array<int,string> $_chunks an array of chunks of text split by spaces
     *
     * @return array<int,string>
     *
     */
    protected function buildString(array $_chunks): array
    {
        $data = [];
        $c = 0;
        $in = false;

        foreach($_chunks as $r)
        {
            $r = trim($r);
            if (strlen($r) == 0)
            {
                continue;
            }

            if ( ($r[0] == '"') && ($r[strlen($r) - 1] == '"') && ($r[strlen($r) - 2] != '\\') )
            {
                $data[$c] = $r;
                ++$c;
                $in = false;

            } else if ($r[0] == '"')
            {
                $data[$c] = $r;
                $in = true;

            } else if ( ($r[strlen($r) - 1] == '"') && ($r[strlen($r) - 2] != '\\') )
            {
                $data[$c] .= ' ' . $r;
                ++$c;  
                $in = false;

            } else
            {
                if ($in == true)
                {
                    $data[$c] .= ' ' . $r;
                } else
                {
                    $data[$c++] = $r;
                }
            }
        }        

        foreach($data as $index => $string)
        {
            $data[$index] = str_replace('\"', '"', trim($string, '"'));
        }

        return $data;
    }

    /**
     * builds a new \NetDNS2\RR object
     *
     * @param \NetDNS2\Packet     &$_packet a \NetDNS2\Packet packet or null to create an empty object
     * @param array<string,mixed> $_rr      an array with RR parse values or null to create an empty object
     *
     * @throws \NetDNS2\Exception
     *
     */
    public function set(\NetDNS2\Packet &$_packet, array $_rr): bool
    {
        $this->name = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC1035, $_rr['name']);

        $this->type = \NetDNS2\ENUM\RRType::set($_rr['type']);

        //
        // for RR OPT (41), the class value includes the requestors UDP payload size, and not a class value
        //
        if ($this->type == \NetDNS2\ENUM\RRType::OPT)
        {
            $this->udp_length = intval($_rr['class']);
        } else
        {
            $this->class = \NetDNS2\ENUM\RRClass::set($_rr['class']);
        }

        $this->ttl      = $_rr['ttl'];
        $this->rdlength = $_rr['rdlength'];
        $this->rdata    = substr($_packet->rdata, $_packet->offset, $_rr['rdlength']);

        return $this->rrSet($_packet);
    }

    /**
     * returns a binary packed DNS RR object
     *
     * @param \NetDNS2\Packet &$_packet a \NetDNS2\Packet packet used for compressing names
     *
     * @throws \NetDNS2\Exception
     *
     */
    public function get(\NetDNS2\Packet &$_packet): string
    {
        $data  = '';
        $rdata = '';

        //
        // compress the name
        //
        $data = $this->name->encode($_packet->offset);

        //
        // pack the main values
        //
        if ($this->type == \NetDNS2\ENUM\RRType::OPT)
        {
            //
            // pre-build the TTL value
            //
            $this->pre_build(); // @phpstan-ignore-line

            //
            // the class value is different for OPT types
            //
            $data .= pack('nnN', $this->type->value, $this->udp_length, $this->ttl);

        } else
        {
            $data .= pack('nnN', $this->type->value, $this->class->value, $this->ttl);
        }

        $_packet->offset += 8;

        //
        // get the RR specific details
        //
        if ($this->rdlength != -1)
        {
            $rdata = $this->rrGet($_packet);
        }

        //
        // add the RR
        //
        if (strlen($rdata) > 0)
        {
            $data .= pack('n', strlen($rdata)) . $rdata;
        } else
        {
            $data .= pack('n', 0);
        }

        $_packet->offset += 2;

        return $data;
    }

    /**
     * parses a binary packet, and returns the appropriate \NetDNS2\RR object, based on the RR type of the binary content.
     *
     * @param \NetDNS2\Packet &$_packet a \NetDNS2\Packet packet used for decompressing names
     *
     * @return object                   returns a new \NetDNS2\RR\* object for the given RR
     * @throws \NetDNS2\Exception
     *
     */
    public static function parse(\NetDNS2\Packet &$_packet): ?object
    {
        $object = [];

        //
        // validate the packet size
        //
        if ($_packet->rdlength == $_packet->offset)
        {
            return null;
        }
        if ($_packet->rdlength < ($_packet->offset + 10))
        {
            throw new \NetDNS2\Exception('failed to parse resource record: packet too small.', \NetDNS2\ENUM\Error::PARSE_ERROR);
        }

        //
        // expand the name
        //
        $object['name'] = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC1035, $_packet, $_packet->offset);

        //
        // unpack the RR details
        //
        $object['type']  = ord($_packet->rdata[$_packet->offset++]) << 8 | ord($_packet->rdata[$_packet->offset++]);
        $object['class'] = ord($_packet->rdata[$_packet->offset++]) << 8 | ord($_packet->rdata[$_packet->offset++]);
        $object['ttl']   = ord($_packet->rdata[$_packet->offset++]) << 24 | ord($_packet->rdata[$_packet->offset++]) << 16 | 
                           ord($_packet->rdata[$_packet->offset++]) << 8 | ord($_packet->rdata[$_packet->offset++]);

        $object['rdlength'] = ord($_packet->rdata[$_packet->offset++]) << 8 | ord($_packet->rdata[$_packet->offset++]);

        if ($_packet->rdlength < ($_packet->offset + $object['rdlength']))
        {
            return null;
        }

        //
        // lookup the class to use
        //
        $o = new (\NetDNS2\ENUM\RRType::set($object['type'])->class())($_packet, $object);

        $_packet->offset += $object['rdlength'];

        return clone $o;
    }

    /**
     * does some basic sanitization
     * 
     */
    public function sanitize(?string $_data, bool $_strip_space = true): string
    {
        if (is_null($_data) == true)
        {
            return '';
        }

        if ($_strip_space == true)
        {
            return strip_tags(strtolower(rtrim($_data, " \n\r\t\v\x00.")));
        } else
        {
            return strtolower(rtrim($_data, '.'));
        }
    }

    /**
     * parses a standard RR format lines, as defined by rfc1035 (kinda)
     *
     * In our implementation, the domain *must* be specified- format must be
     *
     *        <name> [<ttl>] [<class>] <type> <rdata>
     * or
     *        <name> [<class>] [<ttl>] <type> <rdata>
     *
     * name, title, class and type are parsed by this function, rdata is passed to the RR specific classes for parsing.
     *
     * @param string $_line a standard DNS config line 
     *
     * @return object       returns a new \NetDNS2\RR\* object for the given RR
     * @throws \NetDNS2\Exception
     *
     */
    public static function fromString(string $_line): object
    {
        if (strlen($_line) == 0)
        {
            throw new \NetDNS2\Exception('empty config line provided.', \NetDNS2\ENUM\Error::PARSE_ERROR);
        }

        $name  = '';
        $type  = \NetDNS2\ENUM\RRType::set('SOA');
        $class = \NetDNS2\ENUM\RRClass::set('IN');
        $ttl   = 86400;

        //
        // split the line by spaces
        //
        $values = preg_split('/[\s]+/', $_line);
        if ( ($values === false) || (count((array)$values) < 3) )
        {
            throw new \NetDNS2\Exception('failed to parse config: minimum of name, type and rdata required.', \NetDNS2\ENUM\Error::PARSE_ERROR);
        }

        //
        // assume the first value is the name
        //
        $name = trim(strtolower(array_shift($values)), '.');

        //
        // The next value is either a TTL, Class or Type
        //
        foreach((array)$values as $value)
        {
            switch(true)
            {
                case is_numeric($value):
                {
                    $ttl = intval(array_shift($values));
                }
                break;

                //
                // this is here because of a bug in is_numeric() in certain versions of PHP on windows.
                //
                case ($value === 0): // @phpstan-ignore-line
                {
                    $ttl = intval(array_shift($values));
                }
                break;
                case (\NetDNS2\ENUM\RRClass::exists(strval($value)) == true):
                {
                    $class = \NetDNS2\ENUM\RRClass::set(array_shift($values));
                }
                break;
                case (\NetDNS2\ENUM\RRType::exists(strval($value)) == true):
                {
                    $type = \NetDNS2\ENUM\RRType::set(array_shift($values));
                    break 2;
                }
                default:
                {
                    throw new \NetDNS2\Exception('invalid config line provided: unknown file: ' . $value, \NetDNS2\ENUM\Error::PARSE_ERROR);
                }
            }
        }

        /**
          * @var \NetDNS2\RR $o
          */
        $o = new ($type->class());

        //
        // set the parsed values
        //
        $o->name  = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC1035, $name);
        $o->class = $class;
        $o->ttl   = $ttl;

        //
        // parse the rdata
        //
        if ($o->rrFromString($values) === false)
        {
            throw new \NetDNS2\Exception('failed to parse rdata for config: ' . $_line, \NetDNS2\ENUM\Error::PARSE_ERROR);
        }

        return clone $o;
    }
}
