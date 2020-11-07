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
 * The main dynamic DNS notifier class.
 *
 * This class provices functions to handle DNS notify requests as defined by RFC 1996.
 *
 * This is separate from the \NetDNS2\Resolver class, as while the underlying
 * protocol is the same, the functionality is completely different.
 *
 * Generally, query (recursive) lookups are done against caching server, while
 * notify requests are done against authoratative servers.
 *
 */
class Notifier extends \NetDNS2\Client
{
    /*
     * a \NetDNS2\Packet\Request object used for the notify request
     */
    private $_packet;

    /**
     * Constructor - builds a new \NetDNS2\Notifier objected used for doing 
     * DNS notification for a changed zone
     *
     * @param string $zone    the domain name to use for DNS updates
     * @param mixed  $options an array of config options or null
     *
     * @throws \NetDNS2\Exception
     * @access public
     *
     */
    public function __construct($zone, array $options = null)
    {
        parent::__construct($options);

        //
        // create the packet
        //
        $this->_packet = new \NetDNS2\Packet\Request(
            strtolower(trim($zone, " \n\r\t.")), 'SOA', 'IN'
        );

        //
        // make sure the opcode on the packet is set to NOTIFY
        //
        $this->_packet->header->opcode = \NetDNS2\Lookups::OPCODE_NOTIFY;
    }

    /**
     * checks that the given name matches the name for the zone we're notifying
     *
     * @param string $name The name to be checked.
     *
     * @return boolean
     * @throws \NetDNS2\Exception
     * @access private
     *
     */
    private function _checkName($name)
    {
        if (!preg_match('/' . $this->_packet->question[0]->qname . '$/', $name)) {
            
            throw new \NetDNS2\Exception(
                'name provided (' . $name . ') does not match zone name (' .
                $this->_packet->question[0]->qname . ')',
                \NetDNS2\Lookups::E_PACKET_INVALID
            );
        }
    
        return true;
    }

    /**
     *   3.7 - Add RR to notify
     *
     * @param \NetDNS2\RR $rr the \NetDNS2\RR object to be sent in the notify message
     *
     * @return boolean
     * @throws \NetDNS2\Exception
     * @access public
     *
     */
    public function add(\NetDNS2\RR $rr)
    {
        $this->_checkName($rr->name);
        //
        // add the RR to the "notify" section
        //
        if (!in_array($rr, $this->_packet->answer)) {
            $this->_packet->answer[] = $rr;
        }
        return true;
    }

    /**
     * add a signature to the request for authentication 
     *
     * @param string $keyname   the key name to use for the TSIG RR
     * @param string $signature the key to sign the request.
     *
     * @return     boolean
     * @access     public
     * @see        \NetDNS2\Client::signTSIG()
     * @deprecated function deprecated in 1.1.0
     *
     */
    public function signature($keyname, $signature, $algorithm = \NetDNS2\RR\TSIG::HMAC_MD5)
    {
        return $this->signTSIG($keyname, $signature, $algorithm);
    }

    /**
     * returns the current internal packet object.
     *
     * @return \NetDNS2\Packet\Request
     * @access public
     #
     */
    public function packet()
    {
        //
        // take a copy
        //
        $p = $this->_packet;

        //
        // check for an authentication method; either TSIG or SIG
        //
        if (   ($this->auth_signature instanceof \NetDNS2\RR\TSIG) 
            || ($this->auth_signature instanceof \NetDNS2\RR\SIG)
        ) {
            $p->additional[] = $this->auth_signature;
        }

        //
        // update the counts
        //
        $p->header->qdcount = count($p->question);
        $p->header->ancount = count($p->answer);
        $p->header->nscount = count($p->authority);
        $p->header->arcount = count($p->additional);

        return $p;
    }

    /**
     * executes the notify request
     *
     * @param \NetDNS2\Packet\Response &$response ref to the response object
     *
     * @return boolean
     * @throws \NetDNS2\Exception
     * @access public
     *
     */
    public function notify(&$response = null)
    {
        //
        // check for an authentication method; either TSIG or SIG
        //
        if (   ($this->auth_signature instanceof \NetDNS2\RR\TSIG) 
            || ($this->auth_signature instanceof \NetDNS2\RR\SIG)
        ) {
            $this->_packet->additional[] = $this->auth_signature;
        }

        //
        // update the counts
        //
        $this->_packet->header->qdcount = count($this->_packet->question);
        $this->_packet->header->ancount = count($this->_packet->answer);
        $this->_packet->header->nscount = count($this->_packet->authority);
        $this->_packet->header->arcount = count($this->_packet->additional);

        //
        // make sure we have some data to send
        //
        if ($this->_packet->header->qdcount == 0) {
            throw new \NetDNS2\Exception(
                'empty headers- nothing to send!',
                \NetDNS2\Lookups::E_PACKET_INVALID
            );
        }

        //
        // send the packet and get back the response
        //
        $response = $this->sendPacket($this->_packet, $this->use_tcp);

        //
        // clear the internal packet so if we make another request, we don't have
        // old data being sent.
        //
        $this->_packet->reset();

        //
        // for notifies, we just need to know it worked- we don't actualy need to
        // return the response object
        //
        return true;
    }
}
