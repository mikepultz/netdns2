<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2025, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   NetDNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2025 Mike Pultz <mike@mikepultz.com>
 * @license   https://opensource.org/license/bsd-3-clause/ BSD-3-Clause
 * @link      https://netdns2.com/
 * @since     1.6.0
 *
 */

namespace NetDNS2\RR\OPT;

/**
 * RFC 7828 - The edns-tcp-keepalive EDNS0 Option
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-------------------------------+-------------------------------+
 *   !         OPTION-CODE           !         OPTION-LENGTH         !
 *   +-------------------------------+-------------------------------+
 *   |           TIMEOUT             !
 *   +-------------------------------+
 *
 */
final class KEEPALIVE extends \NetDNS2\RR\OPT
{
    /**
     * an idle timeout value for the TCP connection, specified in units of 100 milliseconds, encoded in network byte order.
     */
    protected int $timeout = 0;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->option_code->label() . ' ' . $this->option_length . ' ' . $this->timeout;
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
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
        if ($this->option_length == 0)
        {
            return true;
        }

        $val = unpack('nx', $this->option_data);
        if ($val == false)
        {
            return false;
        }

        list('x' => $this->timeout) = (array)$val;

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if ($this->timeout > 0)
        {
            $this->option_length = 2;
            $this->option_data   = pack('n', $this->timeout);
        } else
        {
            $this->option_length = 0;
            $this->option_data   = '';
        }

        //
        // build the parent OPT data
        //
        return parent::rrGet($_packet);        
    }
}
