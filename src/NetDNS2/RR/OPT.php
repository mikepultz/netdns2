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
 * @since     File available since Release 1.0.0
 *
 */

namespace NetDNS2\RR;

/**
 * OPT Resource Record - RFC2929 section 3.1
 *
 *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    |                          OPTION-CODE                          |
 *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    |                         OPTION-LENGTH                         |
 *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    |                                                               |
 *    /                          OPTION-DATA                          /
 *    /                                                               /
 *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *
 */
class OPT extends \NetDNS2\RR
{
    /*
     * option code - assigned by IANA
     */
    public $option_code = 0;

    /*
     * the length of the option data
     */
    public $option_length = 0;

    /*
     * the option data
     */
    public $option_data = null;

    /*
     * the extended response code stored in the TTL
     */
    public $extended_rcode;

    /*
     * the implementation level
     */
    public $version;

    /*
     * the DO bit used for DNSSEC - RFC3225
     */
    public $do;

    /*
     * the extended flags
     */
    public $z;

    /**
     * Constructor - builds a new \NetDNS2\RR\OPT object; normally you wouldn't call
     * this directly, but OPT RR's are a little different
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
        //
        // this is for when we're manually building an OPT RR object; we aren't
        // passing in binary data to parse, we just want a clean/empty object.
        //
        $this->type             = 'OPT';
        $this->rdlength         = 0;

        $this->option_length    = 0;
        $this->extended_rcode   = 0;
        $this->version          = 0;
        $this->do               = 0;
        $this->z                = 0;

        //
        // everthing else gets passed through to the parent.
        //
        if ( (!is_null($packet)) && (!is_null($rr)) ) {

            parent::__construct($packet, $rr);
        }
    }

    /**
     * method to return the rdata portion of the packet as a string. There is no
     * defintion for returning an OPT RR by string- this is just here to validate
     * the binary parsing / building routines.
     *
     * @return  string
     * @access  protected
     *
     */
    protected function rrToString()
    {
        return $this->option_code . ' ' . $this->option_data;
    }

    /**
     * parses the rdata portion from a standard DNS config line. There is no 
     * definition for parsing a OPT RR by string- this is just here to validate
     * the binary parsing / building routines.
     *
     * @param array $rdata a string split line of values for the rdata
     *
     * @return boolean
     * @access protected
     *
     */
    protected function rrFromString(array $rdata)
    {
        $this->option_code      = array_shift($rdata);
        $this->option_data      = array_shift($rdata);
        $this->option_length    = strlen($this->option_data);

        $x = unpack('Cextended/Cversion/Cdo/Cz', pack('N', $this->ttl));

        $this->extended_rcode   = $x['extended'];
        $this->version          = $x['version'];
        $this->do               = ($x['do'] >> 7);
        $this->z                = $x['z'];

        return true;
    }

    /**
     * parses the rdata of the \NetDNS2\Packet object
     *
     * @param \NetDNS2\Packet &$packet a \NetDNS2\Packet packet to parse the RR from
     *
     * @return boolean
     * @access protected
     *
     */
    protected function rrSet(\NetDNS2\Packet &$packet)
    {
        //
        // parse out the TTL value
        //
        $x = unpack('Cextended/Cversion/Cdo/Cz', pack('N', $this->ttl));

        $this->extended_rcode   = $x['extended'];
        $this->version          = $x['version'];
        $this->do               = ($x['do'] >> 7);
        $this->z                = $x['z'];

        //
        // parse the data, if there is any
        //
        if ($this->rdlength > 0) {

            //
            // unpack the code and length
            //
            $x = unpack('noption_code/noption_length', $this->rdata);

            $this->option_code      = $x['option_code'];
            $this->option_length    = $x['option_length'];

            //
            // copy out the data based on the length
            //
            $this->option_data      = substr($this->rdata, 4);
        }

        return true;
    }

    /**
     * pre-builds the TTL value for this record; we needed to separate this out
     * from the rrGet() function, as the logic in the \NetDNS2\RR packs the TTL
     * value before it builds the rdata value.
     *
     * @return void
     * @access protected
     *
     */
    protected function preBuild()
    {
        //
        // build the TTL value based on the local values
        //
        $ttl = unpack(
            'N', 
            pack('CCCC', $this->extended_rcode, $this->version, ($this->do << 7), 0)
        );

        $this->ttl = $ttl[1];

        return;
    }

    /**
     * returns the rdata portion of the DNS packet
     *
     * @param \NetDNS2\Packet &$packet a \NetDNS2\Packet packet use for
     *                                 compressed names
     *
     * @return mixed                   either returns a binary packed
     *                                 string or null on failure
     * @access protected
     *
     */
    protected function rrGet(\NetDNS2\Packet &$packet)
    {
        //
        // if there is an option code, then pack that data too
        //
        if ($this->option_code > 0) {

            $data = pack('nn', $this->option_code, $this->option_length) . $this->option_data;

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
