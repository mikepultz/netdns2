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
 * @since     1.0.0
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
final class OPT extends \NetDNS2\RR
{
    /**
     * option code - assigned by IANA
     */
    protected int $option_code = 0;

    /**
     * the length of the option data
     */
    protected int $option_length = 0;

    /**
     * the option data
     */
    protected string $option_data = '';

    /**
     * the extended response code stored in the TTL
     */
    protected int $extended_rcode;

    /**
     * the implementation level
     */
    protected int $version;

    /**
     * the extended flags (z)
     */
    protected int $z;

    /**
     * the DO bit used for DNSSEC - RFC3225
     */
    protected int $do;

    /**
     * Constructor - builds a new \NetDNS2\RR\OPT object; normally you wouldn't call this directly, but OPT RR's are a little different
     *
     * @param \NetDNS2\Packet     &$_packet a \NetDNS2\Packet packet or null to create an empty object
     * @param array<string,mixed> $_rr      an array with RR parse values or null to create an empty object
     *
     * @throws \NetDNS2\Exception
     *
     */
    public function __construct(?\NetDNS2\Packet &$_packet = null, ?array $_rr = null)
    {
        //
        // this is for when we're manually building an OPT RR object; we aren't
        // passing in binary data to parse, we just want a clean/empty object.
        //
        $this->name           = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_RFC1035, '');
        $this->type           = \NetDNS2\ENUM\RRType::set('OPT');
        $this->rdlength       = 0;

        $this->option_length  = 0;
        $this->extended_rcode = 0;
        $this->version        = 0;
        $this->z              = 0;
        $this->do             = 0;

        //
        // everthing else gets passed through to the parent.
        //
        if ( (is_null($_packet) == false) && (is_null($_rr) == false) )
        {
            parent::__construct($_packet, $_rr);
        }
    }

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->option_code . ' ' . $this->option_data;
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        return true;
    }

    /**
     * @see \NetDNS2\RR::rrSet()
     */
    protected function rrSet(\NetDNS2\Packet &$_packet): bool
    {
        //
        // parse out the TTL value
        //
        $val = unpack('Cx/Cy/nz', pack('N', $this->ttl));
        if ($val === false)
        {
            return false;
        }

        list('x' => $this->extended_rcode, 'y' => $this->version, 'z' => $this->z) = (array)$val;

        $this->do = ($this->z >> 15);

        //
        // parse the data, if there is any
        //
        if ($this->rdlength > 0)
        {
            //
            // unpack the code and length
            //
            $val = unpack('ny/nz', $this->rdata);
            if ($val === false)
            {
                return false;
            }

            list('y' => $this->option_code, 'z' => $this->option_length) = (array)$val;

            //
            // copy out the data based on the length
            //
            $this->option_data = substr($this->rdata, 4);
        }

        return true;
    }

    /**
     * pre-builds the TTL value for this record; we needed to separate this out from the rrGet() function, as the logic in the \NetDNS2\RR packs the TTL
     * value before it builds the rdata value.
     *
     */
    protected function pre_build(): void
    {
        $this->z = ($this->do << 15);

        //
        // build the TTL value based on the local values
        //
        $val = unpack('Nz', pack('CCn', $this->extended_rcode, $this->version, $this->z));
        if ($val === false)
        {
            return;
        }

        list('z' => $this->ttl) = (array)$val;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if ($this->option_code == 0)
        {
            return '';
        }

        $_packet->offset += strlen($this->option_data) + 4;
    
        return pack('nn', $this->option_code, $this->option_length) . $this->option_data;
    }
}
