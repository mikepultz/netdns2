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
 * @since     File available since Release 1.6.0
 *
 */

namespace NetDNS2;

/**
 * manage the various EDNS0 options that can be passed to the resolver
 *
 */
trait Opts
{
    /*
     * an internal list of \NetDNS2\RR\OPT objects, for passing additional EDNS0 options
     * in a request.
     */
    protected $opts = [];

    /*
     * one callable function to add the various EDNS0 options
     *
     */
    public function __call($name, $args)
    {
        //
        // there should always be boolean as the first value; if it's not here, assume true
        //
        if ( (count($args) == 0) || (is_bool($args[0]) == false) )
        {
            $args[0] = true;
        }

        //
        // if the option is already there, then return right away
        //
        if ( ($args[0] == true) && (isset($this->opts[$name]) == true) )
        {
            return true;

        //
        // removing the option
        //
        } else if ($args[0] == false)
        {
            unset($this->opts[$name]);
            return true;
        }

        //
        // create a new OPT object
        //
        $opt = new \NetDNS2\RR\OPT();

        //
        // based on the type of the option we're adding
        //
        switch($name)
        {
            //
            // DNSSEC DO flag
            //
            case 'dnssec':
            {
                //
                // set the DO flag, and the other values
                //
                $opt->do = 1;
                $opt->class = $this->dnssec_payload_size;
            }
            break;

            //
            // RFC 5001 - DNS Name Server Identifier (NSID) Option
            //
            // usage:
            //
            //      $resolver->nsid(true);      // enable it
            //      $resolver->nsid(false);     // disable it
            //
            case 'nsid':
            {
                $opt->option_code = \NetDNS2\Lookups::EDNS0_OPT_NSID;
            }
            break;

            //
            // RFC 7871 - Client Subnet in DNS Queries
            //
            // usage:
            //
            //      $resolver->subnet(true, '10.10.10.0/24');   // enable it, and pass the given subnet
            //      $resolver->subnet(false);                   // disable it
            //
            case 'subnet':
            {
                // TODO
                //trigger_error('Invalid arguments supplied to ' . __CLASS__ . '::' . $name . '()', E_USER_ERROR);
            }
            break;

            //
            // RFC 7314 - Extension Mechanisms for DNS (EDNS) EXPIRE Option
            //
            // usage:
            //
            //      $resolver->expire(true, 300);   // enable the expire option for 300 seconds
            //      $resolver->expire(false);       // disable the expire option
            //
            case 'expire':
            {
                //
                // users need to pass a keepalive value in ms as a second argument
                //
                if (isset($args[1]) == false)
                {
                    trigger_error('Invalid arguments supplied to ' . __CLASS__ . '::' . $name . '()', E_USER_ERROR);
                }

                //
                // pack the values in network byte order
                //
                $opt->option_code   = \NetDNS2\Lookups::EDNS0_OPT_EXPIRE;
                $opt->option_length = 4;
                $opt->option_data   = pack('N', $args[1]);
            }
            break;

            //
            // RFC 7872 - Domain Name System (DNS) Cookies
            //
            // usage:
            //
            //      $resolver->cookie(true, 'XXXXXXXX');    // enable cookies, and pass the given value as the cookie
            //      $resolver->cookie(false);               // disable cookies
            //
            case 'cookie':
            {
                $opt->option_code = \NetDNS2\Lookups::EDNS0_OPT_COOKIE;

                $opt->option_length = 8;

                $opt->option_data = pack('a*', '12345678');

                // TODO
            }
            break;

            //
            // RFC 7828 - The edns-tcp-keepalive EDNS0 Option
            //
            // usage:
            //
            //      $resolver->tcp_keepalive(true, 10000);  // enable keepalives for 10 seconds
            //      $resolver->tcp_keepalive(false);        // disable keepalives
            //
            case 'tcp_keepalive':
            {
                //
                // this feature only works if you're using TCP
                //
                if ($this->use_tcp == false)
                {
                    throw new \NetDNS2\Exception('tcp_keepalive can only be used on TCP connections. You must set use_tcp = true.', 
                        \NetDNS2\Lookups::E_TCP_REQUIRED);
                }

                //
                // users need to pass a keepalive value in ms as a second argument
                //
                if (isset($args[1]) == false)
                {
                    trigger_error('Invalid arguments supplied to ' . __CLASS__ . '::' . $name . '()', E_USER_ERROR);
                }
                
                //
                // an idle timeout value for the TCP connection, specified in units of 
                // 100 milliseconds, encoded in network byte order.
                //
                $opt->option_code   = \NetDNS2\Lookups::EDNS0_OPT_TCP_KEEPALIVE;
                $opt->option_length = 2;
                $opt->option_data   = pack('n', $args[1]);
            }
            break;

            //
            // RFC 7830 - The EDNS(0) Padding Option
            //
            // usage:
            //
            //      $resolver->padding(true, 8);    // enable it with 8 bytes of padding
            //      $resolver->padding(false);      // disable it
            //
            case 'padding':
            {
                //
                // users need to pass a padding value in bytes as a second argument
                //
                if (isset($args[1]) == false)
                {
                    trigger_error('Invalid arguments supplied to ' . __CLASS__ . '::' . $name . '()', E_USER_ERROR);
                }

                //
                // The OPTION-LENGTH for the "Padding" option is the size (in octets) of
                // the PADDING.  The minimum number of PADDING octets is 0.
                //
                // The PADDING octets SHOULD be set to 0x00.
                //
                $opt->option_code   = \NetDNS2\Lookups::EDNS0_OPT_PADDING;
                $opt->option_length = $args[1];
                $opt->option_data   = pack("x$args[1]");
            }
            break;

            //
            // unknown option
            //
            default:
            {
                trigger_error('Call to undefined method ' . __CLASS__ . '::' . $name . '()', E_USER_ERROR);
                return false;
            }
        }

        //
        // store it on to the options list; this will be added to additional[] later
        //
        $this->opts[$name] = $opt;

        return true;
    }
}
