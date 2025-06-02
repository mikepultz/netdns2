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
 * @since     1.2.5
 *
 */

namespace NetDNS2\RR;

/**
 * TYPE65534 - Private space
 *
 * Since Bind 9.8 beta, it use a private recode as documented in the Bind ARM, chapter 4, "Private-type records. Basically they store 
 * signing process state.
 *
 */
final class TYPE65534 extends \NetDNS2\RR
{
    /**
     * The Private data field
     */
    protected string $private_data;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return base64_encode($this->private_data);
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->private_data = base64_decode(implode('', $_rdata));
        if ($this->private_data === false)
        {
            $this->private_data = '';
        }

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrSet()
     */
    protected function rrSet(\NetDNS2\Packet &$_packet): bool
    {
        if ($this->rdlength == 0)
        {
            return false;
        }
            
        $this->private_data  = $this->rdata;

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if (strlen($this->private_data) == 0)
        {
            return '';
        }

        $_packet->offset += strlen($this->private_data);

        return $this->private_data;
    }
}
