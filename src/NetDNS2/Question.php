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
 * This class handles parsing and constructing the question sectino of DNS
 * packets.
 *
 * This is referred to as the "zone" for update per RFC2136
 *
 * DNS question format - RFC1035 section 4.1.2
 *
 *      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                                               |
 *    /                     QNAME                     /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                     QTYPE                     |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                     QCLASS                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
class Question
{
    /*
     * The name of the question
     *
     * referred to as "zname" for updates per RFC2136
     *
     */
    public $qname;

    /*
     * The RR type for the questino
     *
     * referred to as "ztype" for updates per RFC2136
     *
     */
    public $qtype;
    
    /*
     * The RR class for the questino
     *
     * referred to as "zclass" for updates per RFC2136
     *
     */
    public $qclass;

    /**
     * Constructor - builds a new \NetDNS2\Question object
     *
     * @param mixed &$packet either a \NetDNS2\Packet object, or null to 
     *                       build an empty object
     *
     * @throws \NetDNS2\Exception
     * @access public
     *
     */
    public function __construct(\NetDNS2\Packet &$packet = null)
    {
        if (!is_null($packet)) {

            $this->set($packet);
        } else {

            $this->qname    = '';
            $this->qtype    = 'A';
            $this->qclass   = 'IN';
        }
    }

    /**
     * magic __toString() function to return the \NetDNS2\Question object as a string
     *
     * @return string
     * @access public
     *
     */
    public function __toString()
    {
        return ";;\n;; Question:\n;;\t " . $this->qname . '. ' . 
            $this->qtype . ' ' . $this->qclass . "\n";
    }

    /**
     * builds a new \NetDNS2\Header object from a \NetDNS2\Packet object
     *
     * @param \NetDNS2\Packet &$packet a \NetDNS2\Packet object
     *
     * @return boolean
     * @throws \NetDNS2\Exception
     * @access public
     *
     */
    public function set(\NetDNS2\Packet &$packet)
    {
        //
        // expand the name
        //
        $this->qname = $packet->expand($packet, $packet->offset);
        if ($packet->rdlength < ($packet->offset + 4)) {

            throw new \NetDNS2\Exception(
                'invalid question section: to small',
                \NetDNS2\Lookups::E_QUESTION_INVALID
            );
        }

        //
        // unpack the type and class
        //
        $type   = ord($packet->rdata[$packet->offset++]) << 8 | 
            ord($packet->rdata[$packet->offset++]);
        $class  = ord($packet->rdata[$packet->offset++]) << 8 | 
            ord($packet->rdata[$packet->offset++]);

        //
        // validate it
        //
        $type_name  = \NetDNS2\Lookups::$rr_types_by_id[$type];
        $class_name = \NetDNS2\Lookups::$classes_by_id[$class];

        if ( (!isset($type_name)) || (!isset($class_name)) ) {

            throw new \NetDNS2\Exception(
                'invalid question section: invalid type (' . $type . 
                ') or class (' . $class . ') specified.',
                \NetDNS2\Lookups::E_QUESTION_INVALID
            );
        }

        //
        // store it
        //
        $this->qtype     = $type_name;
        $this->qclass    = $class_name;

        return true;
    }

    /**
     * returns a binary packed \NetDNS2\Question object
     *
     * @param \NetDNS2\Packet &$packet the \NetDNS2\Packet object this question is 
     *                                 part of. This needs to be passed in so that
     *                                 the compressed qname value can be packed in
     *                                 with the names of the other parts of the 
     *                                 packet.
     *
     * @return string
     * @throws \NetDNS2\Exception
     * @access public
     *
     */
    public function get(\NetDNS2\Packet &$packet)
    {
        //
        // validate the type and class
        //
        $type  = \NetDNS2\Lookups::$rr_types_by_name[$this->qtype];
        $class = \NetDNS2\Lookups::$classes_by_name[$this->qclass];

        if ( (!isset($type)) || (!isset($class)) ) {

            throw new \NetDNS2\Exception(
                'invalid question section: invalid type (' . $this->qtype . 
                ') or class (' . $this->qclass . ') specified.',
                \NetDNS2\Lookups::E_QUESTION_INVALID
            );
        }

        $data = $packet->compress($this->qname, $packet->offset);

        $data .= chr($type >> 8) . chr($type) . chr($class >> 8) . chr($class);
        $packet->offset += 4;

        return $data;
    }
}
