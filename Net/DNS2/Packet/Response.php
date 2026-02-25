<?php declare(strict_types=1);

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
 */

class Net_DNS2_Packet_Response extends Net_DNS2_Packet
{
    public string $answer_from = '';
    public int $answer_socket_type = 0;
    public float $response_time = 0.0;

    /**
     * @throws Net_DNS2_Exception
     */
    public function __construct(string $data, int $size)
    {
        $this->set($data, $size);
    }

    /**
     * @throws Net_DNS2_Exception
     */
    public function set(string $data, int $size): bool
    {
        $this->rdata    = $data;
        $this->rdlength = $size;

        $this->header = new Net_DNS2_Header($this);

        if ($this->header->tc === 1) {
            return false;
        }

        for ($x = 0; $x < $this->header->qdcount; ++$x) {
            $this->question[$x] = new Net_DNS2_Question($this);
        }

        for ($x = 0; $x < $this->header->ancount; ++$x) {
            $o = Net_DNS2_RR::parse($this);
            if ($o !== null) {
                $this->answer[] = $o;
            }
        }

        for ($x = 0; $x < $this->header->nscount; ++$x) {
            $o = Net_DNS2_RR::parse($this);
            if ($o !== null) {
                $this->authority[] = $o;
            }
        }

        for ($x = 0; $x < $this->header->arcount; ++$x) {
            $o = Net_DNS2_RR::parse($this);
            if ($o !== null) {
                $this->additional[] = $o;
            }
        }

        return true;
    }
}
