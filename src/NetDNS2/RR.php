<?php

/**
 * DNS Library for handling lookups and updates. 
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   NetDNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 * @since     File available since Release 0.6.0
 *
 */

namespace NetDNS2;

/**
 * This is the base class for DNS Resource Records
 *
 * Each resource record type (defined in RR/*.php) extends this class for
 * base functionality.
 *
 * This class handles parsing and constructing the common parts of the DNS
 * resource records, while the RR specific functionality is handled in each
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
abstract class RR
{
    /*
     * The name of the resource record
     */
    public $name;

    /*
     * The resource record type
     */
    public $type;

    /*
     * The resouce record class
     */
    public $class;

    /*
     * The time to live for this resource record
     */
    public $ttl;

    /*
     * The length of the rdata field
     */
    public $rdlength;

    /*
     * The resource record specific data as a packed binary string
     */
    public $rdata;

    /**
     * abstract definition - method to return a RR as a string; not to 
     * be confused with the __toString() magic method.
     *
     * @return string
     * @access protected
     *
     */
    abstract protected function rrToString();

    /**
     * abstract definition - parses a RR from a standard DNS config line
     *
     * @param array $rdata a string split line of values for the rdata
     *
     * @return boolean
     * @access protected
     *
     */
    abstract protected function rrFromString(array $rdata);

    /**
     * abstract definition - sets a \NetDNS2\RR from a \NetDNS2\Packet object
     *
     * @param \NetDNS2\Packet &$packet a \NetDNS2\Packet packet to parse the RR from
     *
     * @return boolean
     * @access protected
     *
     */
    abstract protected function rrSet(\NetDNS2\Packet &$packet);

    /**
     * abstract definition - returns a binary packet DNS RR object
     *
     * @param \NetDNS2\Packet &$packet a \NetDNS2\Packet packet use for 
     *                                 compressed names
     *
     * @return mixed                   either returns a binary packed string or 
     *                                 null on failure
     * @access protected
     *
     */
    abstract protected function rrGet(\NetDNS2\Packet &$packet);

    /**
     * Constructor - builds a new \NetDNS2\RR object
     *
     * @param \NetDNS2\Packet &$packet a \NetDNS2\Packet packet or null to create 
     *                                 an empty object
     * @param array           $rr      an array with RR parse values or null to 
     *                                 create an empty object
     *
     * @throws \NetDNS2\Exception
     * @access public
     *
     */
    public function __construct(\NetDNS2\Packet &$packet = null, array $rr = null)
    {
        if ( (is_null($packet) == false) && (is_null($rr) == false) )
        {
            if ($this->set($packet, $rr) == false)
            {
                throw new \NetDNS2\Exception('failed to generate resource record', \NetDNS2\Lookups::E_RR_INVALID);
            }

        } else
        {
            $class = \NetDNS2\Lookups::$rr_types_class_to_id[get_class($this)];
            if (isset($class) == true)
            {
                $this->type = \NetDNS2\Lookups::$rr_types_by_id[$class];
            }

            $this->class    = 'IN';
            $this->ttl      = 86400;
        }
    }

    /**
     * magic __toString() method to return the \NetDNS2\RR object object as a string
     *
     * @return string
     * @access public
     *
     */
    public function __toString()
    {
        return $this->name . '. ' . $this->ttl . ' ' . $this->class . 
            ' ' . $this->type . ' ' . $this->rrToString();
    }

    /**
     * return the same data as __toString(), but as an array, so each value can be 
     * used without having to parse the string.
     *
     * @return array
     * @access public
     *
     */
    public function asArray()
    {
        return [

            'name'  => $this->name,
            'ttl'   => $this->ttl,
            'class' => $this->class,
            'type'  => $this->type,
            'rdata' => $this->rrToString()
        ];
    }

    /**
     * return a formatted string; if a string has spaces in it, then return 
     * it with double quotes around it, otherwise, return it as it was passed in.
     *
     * @param string $string the string to format
     *
     * @return string
     * @access protected
     *
     */
    protected function formatString($string)
    {
        return '"' . str_replace('"', '\"', trim($string, '"')) . '"';
    }
    
    /**
     * builds an array of strings from an array of chunks of text split by spaces
     *
     * @param array $chunks an array of chunks of text split by spaces
     *
     * @return array
     * @access protected
     *
     */
    protected function buildString(array $chunks)
    {
        $data = [];
        $c = 0;
        $in = false;

        foreach($chunks as $r)
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
     * @param \NetDNS2\Packet &$packet a \NetDNS2\Packet packet or null to create
     *                                 an empty object
     * @param array           $rr      an array with RR parse values or null to 
     *                                 create an empty object
     *
     * @return boolean
     * @throws \NetDNS2\Exception
     * @access public
     *
     */
    public function set(\NetDNS2\Packet &$packet, array $rr)
    {
        $this->name     = $rr['name'];
        $this->type     = \NetDNS2\Lookups::$rr_types_by_id[$rr['type']];

        //
        // for RR OPT (41), the class value includes the requestors UDP payload size,
        // and not a class value
        //
        if ($this->type == 'OPT')
        {
            $this->class = $rr['class'];
        } else
        {
            $this->class = \NetDNS2\Lookups::$classes_by_id[$rr['class']];
        }

        $this->ttl      = $rr['ttl'];
        $this->rdlength = $rr['rdlength'];
        $this->rdata    = substr($packet->rdata, $packet->offset, $rr['rdlength']);

        return $this->rrSet($packet);
    }

    /**
     * returns a binary packed DNS RR object
     *
     * @param \NetDNS2\Packet &$packet a \NetDNS2\Packet packet used for 
     *                                 compressing names
     *
     * @return string
     * @throws \NetDNS2\Exception
     * @access public
     *
     */
    public function get(\NetDNS2\Packet &$packet)
    {
        $data  = '';
        $rdata = '';

        //
        // pack the name
        //
        $data = $packet->compress($this->name, $packet->offset);

        //
        // pack the main values
        //
        if ($this->type == 'OPT')
        {
            //
            // pre-build the TTL value
            //
            $this->preBuild();

            //
            // the class value is different for OPT types
            //
            $data .= pack('nnN', \NetDNS2\Lookups::$rr_types_by_name[$this->type], $this->class, $this->ttl);

        } else
        {
            $data .= pack('nnN', \NetDNS2\Lookups::$rr_types_by_name[$this->type], 
                \NetDNS2\Lookups::$classes_by_name[$this->class], $this->ttl);
        }

        //
        // increase the offset, and allow for the rdlength
        //
        $packet->offset += 10;

        //
        // get the RR specific details
        //
        if ($this->rdlength != -1)
        {
            $rdata = $this->rrGet($packet);
        }

        //
        // add the RR
        //
        $data .= pack('n', strlen($rdata)) . $rdata;

        return $data;
    }

    /**
     * parses a binary packet, and returns the appropriate \NetDNS2\RR object, 
     * based on the RR type of the binary content.
     *
     * @param \NetDNS2\Packet &$packet a \NetDNS2\Packet packet used for 
     *                                 decompressing names
     *
     * @return mixed                   returns a new \NetDNS2\RR\* object for
     *                                 the given RR
     * @throws \NetDNS2\Exception
     * @access public
     *
     */
    public static function parse(\NetDNS2\Packet &$packet)
    {
        $object = [];

        //
        // expand the name
        //
        $object['name'] = $packet->expand($packet, $packet->offset);

        if (is_null($object['name']) == true)
        {
            throw new \NetDNS2\Exception('failed to parse resource record: failed to expand name.', \NetDNS2\Lookups::E_PARSE_ERROR);
        }
        if ($packet->rdlength < ($packet->offset + 10))
        {
            throw new \NetDNS2\Exception('failed to parse resource record: packet too small.', \NetDNS2\Lookups::E_PARSE_ERROR);
        }

        //
        // unpack the RR details
        //
        $object['type']     = ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);
        $object['class']    = ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);

        $object['ttl']      = ord($packet->rdata[$packet->offset++]) << 24 | ord($packet->rdata[$packet->offset++]) << 16 | 
                                ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);

        $object['rdlength'] = ord($packet->rdata[$packet->offset++]) << 8 | ord($packet->rdata[$packet->offset++]);

        if ($packet->rdlength < ($packet->offset + $object['rdlength']))
        {
            return null;
        }

        //
        // lookup the class to use
        //
        $o      = null;
        $class  = \NetDNS2\Lookups::$rr_types_id_to_class[$object['type']];

        if (isset($class) == true)
        {
            $o = new $class($packet, $object);
            if ($o)
            {
                $packet->offset += $object['rdlength'];
            }

        } else
        {
            throw new \NetDNS2\Exception('un-implemented resource record type: ' . $object['type'], \NetDNS2\Lookups::E_RR_INVALID);
        }

        return $o;
    }

    /**
     * cleans up some RR data
     * 
     * @param string $data the text string to clean
     *
     * @return string returns the cleaned string
     *
     * @access public
     *
     */
    public function cleanString($data)
    {
        return strtolower(rtrim($data, '.'));
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
     * name, title, class and type are parsed by this function, rdata is passed
     * to the RR specific classes for parsing.
     *
     * @param string $line a standard DNS config line 
     *
     * @return mixed       returns a new \NetDNS2\RR\* object for the given RR
     * @throws \NetDNS2\Exception
     * @access public
     *
     */
    public static function fromString($line)
    {
        if (strlen($line) == 0)
        {
            throw new \NetDNS2\Exception('empty config line provided.', \NetDNS2\Lookups::E_PARSE_ERROR);
        }

        $name   = '';
        $type   = '';
        $class  = 'IN';
        $ttl    = 86400;

        //
        // split the line by spaces
        //
        $values = preg_split('/[\s]+/', $line);
        if (count($values) < 3)
        {
            throw new \NetDNS2\Exception('failed to parse config: minimum of name, type and rdata required.', \NetDNS2\Lookups::E_PARSE_ERROR);
        }

        //
        // assume the first value is the name
        //
        $name = trim(strtolower(array_shift($values)), '.');

        //
        // The next value is either a TTL, Class or Type
        //
        foreach($values as $value)
        {
            switch(true)
            {
                case is_numeric($value):
                {
                    $ttl = array_shift($values);
                }
                break;

                //
                // this is here because of a bug in is_numeric() in certain versions of
                // PHP on windows.
                //
                case ($value === 0):
                {
                    $ttl = array_shift($values);
                }
                break;
                case isset(\NetDNS2\Lookups::$classes_by_name[strtoupper($value)]):
                {
                    $class = strtoupper(array_shift($values));
                }
                break;
                case isset(\NetDNS2\Lookups::$rr_types_by_name[strtoupper($value)]):
                {
                    $type = strtoupper(array_shift($values));
                    break 2;
                }
                break;
                default:
                {
                    throw new \NetDNS2\Exception('invalid config line provided: unknown file: ' . $value, \NetDNS2\Lookups::E_PARSE_ERROR);
                }
            }
        }

        //
        // lookup the class to use
        //
        $o = null;
        $class_name = \NetDNS2\Lookups::$rr_types_id_to_class[\NetDNS2\Lookups::$rr_types_by_name[$type]];

        if (isset($class_name) == true)
        {
            $o = new $class_name;
            if (is_null($o) == false)
            {
                //
                // set the parsed values
                //
                $o->name    = $name;
                $o->class   = $class;
                $o->ttl     = $ttl;

                //
                // parse the rdata
                //
                if ($o->rrFromString($values) === false)
                {
                    throw new \NetDNS2\Exception('failed to parse rdata for config: ' . $line, \NetDNS2\Lookups::E_PARSE_ERROR);
                }

            } else
            {
                throw new \NetDNS2\Exception('failed to create new RR record for type: ' . $type, \NetDNS2\Lookups::E_RR_INVALID);
            }

        } else
        {
            throw new \NetDNS2\Exception('un-implemented resource record type: '. $type, \NetDNS2\Lookups::E_RR_INVALID);
        }

        return $o;
    }
}
