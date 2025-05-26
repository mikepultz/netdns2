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
 * @since     1.6.0
 *
 */

namespace NetDNS2;

/**
 * manage the various EDNS0 options that can be passed to the resolver
 *
 */
trait Opts
{
    /**
     * EDNS0 Option Codes (OPT)
     */
    public const EDNS0_OPT_LLQ              = 1;
    public const EDNS0_OPT_UL               = 2;
    public const EDNS0_OPT_NSID             = 3;
    public const EDNS0_OPT_DAU              = 5;
    public const EDNS0_OPT_DHU              = 6;
    public const EDNS0_OPT_N3U              = 7;
    public const EDNS0_OPT_CLIENT_SUBNET    = 8;
    public const EDNS0_OPT_EXPIRE           = 9;
    public const EDNS0_OPT_COOKIE           = 10;
    public const EDNS0_OPT_TCP_KEEPALIVE    = 11;
    public const EDNS0_OPT_PADDING          = 12;
    public const EDNS0_OPT_CHAIN            = 13;
    public const EDNS0_OPT_KEY_TAG          = 14;
    public const EDNS0_OPT_EXTENDED_ERROR   = 15;
    public const EDNS0_OPT_CLIENT_TAG       = 16;
    public const EDNS0_OPT_SERVER_TAG       = 17;
    public const EDNS0_OPT_REPORT_CHANNEL   = 18;
    public const EDNS0_OPT_ZONE_VERSION     = 19;
    public const EDNS0_OPT_UMBRELLA_IDENT   = 20292;
    public const EDNS0_OPT_DEVICEID         = 26946;

    /**
     * an internal list of \NetDNS2\RR\OPT objects, for passing additional EDNS0 options in a request.
     *
     * @var array<string,\NetDNS2\RR\OPT>
     */
    protected array $opts = [];

    /**
     * one callable function to add the various EDNS0 options
     *
     * @param array<int,mixed> $_args
     *
     * @throws \NetDNS2\Exception
     *
     */
    public function __call(string $_name, array $_args): bool
    {
        //
        // there should always be boolean as the first value; if it's not here, assume true
        //
        if ( (count($_args) == 0) || (is_bool($_args[0]) == false) )
        {
            $_args[0] = true;
        }

        //
        // if the option is already there, then return right away
        //
        if ( ($_args[0] == true) && (isset($this->opts[$_name]) == true) )
        {
            return true;

        //
        // removing the option
        //
        } else if ($_args[0] == false)
        {
            unset($this->opts[$_name]);
            return true;
        }

        //
        // create a new OPT object
        //
        $opt = new \NetDNS2\RR\OPT();

        //
        // based on the type of the option we're adding
        //
        switch($_name)
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
                $opt->class = \NetDNS2\ENUM\RRClass::set('NONE');
                $opt->udp_length = $this->dnssec_payload_size;
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
                $opt->option_code = self::EDNS0_OPT_NSID;
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
                //trigger_error('Invalid arguments supplied to ' . __CLASS__ . '::' . $_name . '()', E_USER_ERROR);
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
                if (isset($_args[1]) == false)
                {
                    trigger_error('Invalid arguments supplied to ' . __CLASS__ . '::' . $_name . '()', E_USER_ERROR);
                }

                //
                // pack the values in network byte order
                //
                $opt->option_code   = self::EDNS0_OPT_EXPIRE;
                $opt->option_length = 4;
                $opt->option_data   = pack('N', $_args[1]);
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
                $opt->option_code = self::EDNS0_OPT_COOKIE;

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
                        \NetDNS2\ENUM\Error::TCP_REQUIRED);
                }

                //
                // users need to pass a keepalive value in ms as a second argument
                //
                if (isset($_args[1]) == false)
                {
                    trigger_error('Invalid arguments supplied to ' . __CLASS__ . '::' . $_name . '()', E_USER_ERROR);
                }
                
                //
                // an idle timeout value for the TCP connection, specified in units of 
                // 100 milliseconds, encoded in network byte order.
                //
                $opt->option_code   = self::EDNS0_OPT_TCP_KEEPALIVE;
                $opt->option_length = 2;
                $opt->option_data   = pack('n', $_args[1]);
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
                if (isset($_args[1]) == false)
                {
                    trigger_error('Invalid arguments supplied to ' . __CLASS__ . '::' . $_name . '()', E_USER_ERROR);
                }

                //
                // The OPTION-LENGTH for the "Padding" option is the size (in octets) of
                // the PADDING.  The minimum number of PADDING octets is 0.
                //
                // The PADDING octets SHOULD be set to 0x00.
                //
                $opt->option_code   = self::EDNS0_OPT_PADDING;
                $opt->option_length = $_args[1];
                $opt->option_data   = pack("x$_args[1]");
            }
            break;

            //
            // unknown option
            //
            default:
            {
                trigger_error('Call to undefined method ' . __CLASS__ . '::' . $_name . '()', E_USER_ERROR);
            }
        }

        //
        // store it on to the options list; this will be added to additional[] later
        //
        $this->opts[$_name] = $opt;

        return true;
    }
}
