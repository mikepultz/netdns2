<?php

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
 * @since     File available since Release 0.6.0
 *
 */

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
abstract class Net_DNS2_RR
{
    /*
     * The name of the resource record
     */
    public $name = '';

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
     * abstract definition - sets a Net_DNS2_RR from a Net_DNS2_Packet object
     *
     * @param Net_DNS2_Packet &$packet a Net_DNS2_Packet packet to parse the RR from
     *
     * @return boolean
     * @access protected
     *
     */
    abstract protected function rrSet(Net_DNS2_Packet &$packet);

    /**
     * abstract definition - returns a binary packet DNS RR object
     *
     * @param Net_DNS2_Packet &$packet a Net_DNS2_Packet packet use for 
     *                                 compressed names
     *
     * @return mixed                   either returns a binary packed string or 
     *                                 null on failure
     * @access protected
     *
     */
    abstract protected function rrGet(Net_DNS2_Packet &$packet);

    /**
     * Constructor - builds a new Net_DNS2_RR object
     *
     * @param Net_DNS2_Packet &$packet a Net_DNS2_Packet packet or null to create 
     *                                 an empty object
     * @param array           $rr      an array with RR parse values or null to 
     *                                 create an empty object
     *
     * @throws Net_DNS2_Exception
     * @access public
     *
     */
    public function __construct(?Net_DNS2_Packet &$packet = null, ?array $rr = null)
    {
        if ( (!is_null($packet)) && (!is_null($rr)) ) {

            if ($this->set($packet, $rr) == false) {

                throw new Net_DNS2_Exception(
                    'failed to generate resource record',
                    Net_DNS2_Lookups::E_RR_INVALID
                );
            }
        } else {

            $class = Net_DNS2_Lookups::$rr_types_class_to_id[get_class($this)];
            if (isset($class)) {

                $this->type = Net_DNS2_Lookups::$rr_types_by_id[$class];
            }

            $this->class    = 'IN';
            $this->ttl      = 86400;
        }
    }

    /**
     * magic __toString() method to return the Net_DNS2_RR object object as a string
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

        foreach ($chunks as $r) {

            $r = trim($r);
            if (strlen($r) == 0) {
                continue;
            }

            if ( ($r[0] == '"')
                && ($r[strlen($r) - 1] == '"')
                && ($r[strlen($r) - 2] != '\\')
            ) {

                $data[$c] = $r;
                ++$c;
                $in = false;

            } else if ($r[0] == '"') {

                $data[$c] = $r;
                $in = true;

            } else if ( ($r[strlen($r) - 1] == '"')
                && ($r[strlen($r) - 2] != '\\')
            ) {
            
                $data[$c] .= ' ' . $r;
                ++$c;  
                $in = false;

            } else {

                if ($in == true) {
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
     * builds a new Net_DNS2_RR object
     *
     * @param Net_DNS2_Packet &$packet a Net_DNS2_Packet packet or null to create
     *                                 an empty object
     * @param array           $rr      an array with RR parse values or null to 
     *                                 create an empty object
     *
     * @return boolean
     * @throws Net_DNS2_Exception
     * @access public
     *
     */
    public function set(Net_DNS2_Packet &$packet, array $rr)
    {
        $this->name     = $rr['name'];
        $this->type     = Net_DNS2_Lookups::$rr_types_by_id[$rr['type']];

        //
        // for RR OPT (41), the class value includes the requestors UDP payload size,
        // and not a class value
        //
        if ($this->type == 'OPT') {
            $this->class = $rr['class'];
        } else {
            $this->class = Net_DNS2_Lookups::$classes_by_id[$rr['class']];
        }

        $this->ttl      = $rr['ttl'];
        $this->rdlength = $rr['rdlength'];
        $this->rdata    = substr($packet->rdata, $packet->offset, $rr['rdlength']);

        return $this->rrSet($packet);
    }

    /**
     * returns a binary packed DNS RR object
     *
     * @param Net_DNS2_Packet &$packet a Net_DNS2_Packet packet used for 
     *                                 compressing names
     *
     * @return string
     * @throws Net_DNS2_Exception
     * @access public
     *
     */
    public function get(Net_DNS2_Packet &$packet)
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
        if ($this->type == 'OPT') {

            //
            // pre-build the TTL value
            //
            $this->preBuild();  // @phpstan-ignore-line

            //
            // the class value is different for OPT types
            //
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

        //
        // increase the offset, and allow for the rdlength
        //
        $packet->offset += 10;

        //
        // get the RR specific details
        //
        if ($this->rdlength != -1) {

            $rdata = $this->rrGet($packet);
        }

        //
        // add the RR
        //
        if ( (is_null($rdata) == false) && (strlen($rdata) > 0) ) {

            $data .= pack('n', strlen($rdata)) . $rdata;
        } else
        {
            $data .= pack('n', 0);
        }

        return $data;
    }

    /**
     * parses a binary packet, and returns the appropriate Net_DNS2_RR object, 
     * based on the RR type of the binary content.
     *
     * @param Net_DNS2_Packet &$packet a Net_DNS2_Packet packet used for 
     *                                 decompressing names
     *
     * @return mixed                   returns a new Net_DNS2_RR_* object for
     *                                 the given RR
     * @throws Net_DNS2_Exception
     * @access public
     *
     */
    public static function parse(Net_DNS2_Packet &$packet)
    {
        $object = [];

        //
        // expand the name
        //
        $object['name'] = $packet->expand($packet, $packet->offset);
        if (is_null($object['name'])) {

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

        //
        // unpack the RR details
        //
        $object['type']     = ord($packet->rdata[$packet->offset++]) << 8 | 
                                ord($packet->rdata[$packet->offset++]);
        $object['class']    = ord($packet->rdata[$packet->offset++]) << 8 | 
                                ord($packet->rdata[$packet->offset++]);

        $object['ttl']      = ord($packet->rdata[$packet->offset++]) << 24 | 
                                ord($packet->rdata[$packet->offset++]) << 16 | 
                                ord($packet->rdata[$packet->offset++]) << 8 | 
                                ord($packet->rdata[$packet->offset++]);

        $object['rdlength'] = ord($packet->rdata[$packet->offset++]) << 8 | 
                                ord($packet->rdata[$packet->offset++]);

        if ($packet->rdlength < ($packet->offset + $object['rdlength'])) {

            throw new Net_DNS2_Exception(
                'failed to parse resource record: packet too small.',
                Net_DNS2_Lookups::E_PARSE_ERROR
            );
        }

        //
        // lookup the class to use
        //
        if ( (isset(Net_DNS2_Lookups::$rr_types_id_to_class[$object['type']]) == true) &&
            (class_exists(Net_DNS2_Lookups::$rr_types_id_to_class[$object['type']]) == true) ) {

            $o = new Net_DNS2_Lookups::$rr_types_id_to_class[$object['type']]($packet, $object);

            $packet->offset += $object['rdlength'];            

            return $o;
        }

        throw new Net_DNS2_Exception('un-implemented resource record type: ' . $object['type'], Net_DNS2_Lookups::E_RR_INVALID);
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
        return (is_null($data) == true) ? null : strtolower(rtrim($data, '.'));
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
     * @return mixed       returns a new Net_DNS2_RR_* object for the given RR
     * @throws Net_DNS2_Exception
     * @access public
     *
     */
    public static function fromString($line)
    {
        if ( (is_null($line) == true) || (strlen($line) == 0) ) {

            throw new Net_DNS2_Exception(
                'empty config line provided.',
                Net_DNS2_Lookups::E_PARSE_ERROR
            );
        }

        $name   = '';
        $type   = '';
        $class  = 'IN';
        $ttl    = 86400;

        //
        // split the line by spaces
        //
        $values = preg_split('/[\s]+/', $line);
        if ( ($values === false) || (count($values) < 3) ) {

            throw new Net_DNS2_Exception(
                'failed to parse config: minimum of name, type and rdata required.',
                Net_DNS2_Lookups::E_PARSE_ERROR
            );
        }

        //
        // assume the first value is the name
        //
        $name = trim(strtolower(array_shift($values)), '.');

        //
        // The next value is either a TTL, Class or Type
        //
        foreach ($values as $value) {

            switch(true) {
            case is_numeric($value):

                $ttl = array_shift($values);
                break;

            //
            // this is here because of a bug in is_numeric() in certain versions of
            // PHP on windows.
            //
            case ($value === 0):    // @phpstan-ignore-line
                
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
                    'invalid config line provided: unknown file: ' . $value,
                    Net_DNS2_Lookups::E_PARSE_ERROR
                );
            }
        }

        //
        // lookup the class to use
        //
        $o = null;
        $class_name = Net_DNS2_Lookups::$rr_types_id_to_class[
            Net_DNS2_Lookups::$rr_types_by_name[$type]
        ];

        if (isset($class_name)) {

            $o = new $class_name;

            //
            // set the parsed values
            //
            $o->name    = $name;    // @phpstan-ignore-line
            $o->class   = $class;   // @phpstan-ignore-line
            $o->ttl     = $ttl;     // @phpstan-ignore-line

            //
            // parse the rdata
            //
            if ($o->rrFromString($values) === false) {  // @phpstan-ignore-line

                throw new Net_DNS2_Exception(
                    'failed to parse rdata for config: ' . $line,
                    Net_DNS2_Lookups::E_PARSE_ERROR
                );
            }

        } else {

            throw new Net_DNS2_Exception(
                'un-implemented resource record type: '. $type,
                Net_DNS2_Lookups::E_RR_INVALID
            );
        }

        return $o;
    }
}
