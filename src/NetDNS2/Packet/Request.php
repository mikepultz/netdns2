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

namespace NetDNS2\Packet;

/**
 * This class handles building new DNS request packets; packets used for DNS
 * queries and updates.
 *   
 */
class Request extends \NetDNS2\Packet
{
    /**
     * Constructor - builds a new \NetDNS2\Packet\Request object
     *
     * @param string $name  the domain name for the packet
     * @param string $type  the DNS RR type for the packet
     * @param string $class the DNS class for the packet
     *
     * @throws \NetDNS2\Exception
     * @access public
     *
     */
    public function __construct($name, $type = null, $class = null)
    {
        $this->set($name, $type, $class);
    }

    /**
     * builds a new \NetDNS2\Packet\Request object
     *
     * @param string $name  the domain name for the packet
     * @param string $type  the DNS RR type for the packet
     * @param string $class the DNS class for the packet
     *
     * @return boolean
     * @throws \NetDNS2\Exception
     * @access public
     *
     */
    public function set($name, $type = 'A', $class = 'IN')
    {
        //
        // generate a new header
        //
        $this->header = new \NetDNS2\Header;

        //
        // add a new question
        //
        $q = new \NetDNS2\Question();

        //
        // allow queries directly to . for the root name servers
        //
        if ($name != '.')
        {
            $name = trim(strtolower($name), " \t\n\r\0\x0B.");
        }

        $type = strtoupper(trim($type));
        $class = strtoupper(trim($class));

        //
        // check that the input string has some data in it
        //
        if (empty($name) == true)
        {
            throw new \NetDNS2\Exception('empty query string provided', \NetDNS2\Lookups::E_PACKET_INVALID);
        }

        //
        // if the type is "*", rename it to "ANY"- both are acceptable.
        //
        if ($type == '*')
        {
            $type = 'ANY';
        }

        //
        // check that the type and class are valid
        //    
        if ( (isset(\NetDNS2\Lookups::$rr_types_by_name[$type]) == false) || (isset(\NetDNS2\Lookups::$classes_by_name[$class]) == false) )
        {
            throw new \NetDNS2\Exception('invalid type (' . $type . ') or class (' . $class . ') specified.', \NetDNS2\Lookups::E_PACKET_INVALID);
        }

        if ($type == 'PTR')
        {
            //
            // if it's a PTR request for an IP address, then make sure we tack on the arpa domain.
            //
            // there are other types of PTR requests, so if an IP adress doesn't match, then just let it 
            // flow through and assume it's a hostname
            //
            // IPv4
            //
            if (\NetDNS2\Client::isIPv4($name) == true)
            {
                $name = implode('.', array_reverse(explode('.', $name)));
                $name .= '.in-addr.arpa';

            //
            // IPv6
            //
            } else if (\NetDNS2\Client::isIPv6($name) == true)
            {
                $e = \NetDNS2\Client::expandIPv6($name);
                if ($e !== false)
                {
                    $name = implode('.', array_reverse(str_split(str_replace(':', '', $e))));
                    $name .= '.ip6.arpa';

                } else
                {
                    throw new \NetDNS2\Exception('unsupported PTR value: ' . $name, \NetDNS2\Lookups::E_PACKET_INVALID);
                }
            }
        }

        //
        // store the data
        //
        $q->qname           = $name;
        $q->qtype           = $type;
        $q->qclass          = $class;        

        $this->question[]   = $q;

        //
        // the answer, authority and additional are empty; they can be modified
        // after the request is created for UPDATE requests if needed.
        //
        $this->answer       = [];
        $this->authority    = [];
        $this->additional   = [];

        return true;
    }
}
